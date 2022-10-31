package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/kubescape/sneeffer/internal/logger"
	"github.com/kubescape/sneeffer/sneeffer/utils"
	"github.com/xyproto/randomstring"
	"gopkg.in/yaml.v2"
)

type SbomObject struct {
	imageID                string
	sbomData               []byte
	sbomCreateorPath       string
	sbomFilteredFilePath   string
	sbomConfigDirPath      string
	credentialslist        []types.AuthConfig
	sbomUnFilteredFilePath string
}

func CreateSbomObject(credentialslist []types.AuthConfig, imageID string) *SbomObject {
	sbomCreatorPath, _ := os.LookupEnv("sbomCreatorPath")
	innerDataDirPath, _ := os.LookupEnv("innerDataDirPath")

	imageIDPath := strings.ReplaceAll(imageID, "/", "_")

	return &SbomObject{
		imageID:                imageID,
		sbomCreateorPath:       sbomCreatorPath,
		sbomFilteredFilePath:   innerDataDirPath + "/sbom/" + imageIDPath + "-filtered",
		sbomUnFilteredFilePath: innerDataDirPath + "/sbom/" + imageIDPath + "-unfiltered",
		credentialslist:        credentialslist,
		sbomConfigDirPath:      filepath.Dir(sbomCreatorPath),
	}
}

func (vuln *SbomObject) copyFileData(syftConfigPath string) error {
	source, err := os.Open(path.Join(vuln.sbomConfigDirPath, ".syft", "config.yaml"))
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(syftConfigPath)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return err
}

func (sbom *SbomObject) addCredentialsToAnchoreConfigurationFile(configFilePath string, cred types.AuthConfig) error {
	var App Application

	bytes, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(bytes, &App)
	if err != nil {
		return err
	}

	regCred := RegistryCredentials{}

	if cred.Auth != "" {
		regCred.Authority = cred.Auth
	}
	if cred.RegistryToken != "" {
		regCred.Token = cred.RegistryToken
	}
	if cred.Username != "" && cred.Password != "" {
		regCred.Username = cred.Username
		regCred.Password = cred.Password
	}
	if equal := (regCred == RegistryCredentials{}); !equal {
		App.Registry.Auth = append(App.Registry.Auth, regCred)
	}
	if len(App.Registry.Auth) == 0 {
		return fmt.Errorf("no credentials added")
	}

	config_yaml_data, _ := yaml.Marshal(&App)
	err = ioutil.WriteFile(configFilePath, config_yaml_data, 0755)
	if err != nil {
		return err
	}

	return nil
}

func (sbom *SbomObject) CreateSbomUnfilter(errChan chan error) bool {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	configFileName := randomstring.HumanFriendlyEnglishString(rand.Intn(100)) + ".yaml"
	syftConfigPath := path.Join(sbom.sbomConfigDirPath, ".syft", configFileName)
	err := sbom.copyFileData(syftConfigPath)
	if err != nil {
		logger.Print(logger.ERROR, false, "failed to copy default file config to %v with err %v\n", syftConfigPath, err)
		os.Remove(syftConfigPath)
		return false
	}

	for i := 0; i != len(sbom.credentialslist); i++ {
		err := sbom.addCredentialsToAnchoreConfigurationFile(syftConfigPath, sbom.credentialslist[i])
		if err != nil {
			logger.Print(logger.ERROR, false, "failed to copy default file config to %v with err %v\n", syftConfigPath, err)
			os.Remove(syftConfigPath)
			return false
		}
	}

	cmd := exec.Command(sbom.sbomCreateorPath, sbom.imageID, "-o", "json", "-c", syftConfigPath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Print(logger.INFO, false, "start getting sbom command for image %s\n", sbom.imageID)
	logger.Print(logger.DEBUG, false, "cmd.Args %s\n", cmd.Args)
	err = cmd.Run()
	if err != nil {
		logger.Print(logger.ERROR, false, "GetSbom: sbom creator process fail with error %v\n", err)
		logger.Print(logger.ERROR, false, "GetSbom: sbom creator process stderr: \n")
		logger.Print(logger.ERROR, false, "%s\n", stderr.String())
		os.Remove(syftConfigPath)
		errChan <- fmt.Errorf("CreateSbomUnfilter process failed with error %v, stderr: %s", err, stderr.String())
		return false
	}
	sbom.sbomData = stdout.Bytes()
	logger.Print(logger.INFO, false, "the sbom getting finished successesfully for image %s\n", sbom.imageID)

	os.Remove(syftConfigPath)
	errChan <- nil
	return true

}

func (sbom *SbomObject) SetSbom(sbomData []byte) bool {
	sbom.sbomData = sbomData
	return true
}

func contains(needle string, haystack []string) bool {
	for i := range haystack {
		if haystack[i] == needle {
			return true
		}
	}
	return false
}

func (sbom *SbomObject) FilterSbom(realTimeFileList []string) error {
	model := Document{}
	err := json.Unmarshal(sbom.sbomData, &model)
	if err != nil {
		logger.Print(logger.ERROR, false, "Error: failed unmarshall with err %v\n", err)
		return err
	}

	//convert file to id in sbom
	var fileIDsList []string
	for i := range model.Files {
		if contains(model.Files[i].Location.RealPath, realTimeFileList) {
			fileIDsList = append(fileIDsList, model.Files[i].ID)
		}
	}
	logger.Print(logger.DEBUG, false, "fileIDsList size: %d\n", len(fileIDsList))

	//remove irrelavent files by file ids
	for i, rcount, rlen := 0, 0, len(model.Files); i < rlen; i++ {
		j := i - rcount
		if !contains(model.Files[j].ID, fileIDsList) {
			model.Files = append(model.Files[:j], model.Files[j+1:]...)
			rcount++
		}
	}

	//remove irrelavent files by file ids
	for i, rcount, rlen := 0, 0, len(model.ArtifactRelationships); i < rlen; i++ {
		j := i - rcount
		if !contains(model.ArtifactRelationships[j].Child, fileIDsList) {
			model.ArtifactRelationships = append(model.ArtifactRelationships[:j], model.ArtifactRelationships[j+1:]...)
			rcount++
		}
	}
	logger.Print(logger.DEBUG, false, "model.ArtifactRelationships size: %d\n", len(model.ArtifactRelationships))

	//create relavent packageIDs list
	var packageIDs []string
	for i := range model.ArtifactRelationships {
		packageIDs = append(packageIDs, model.ArtifactRelationships[i].Parent)
	}
	logger.Print(logger.DEBUG, false, "packageIDs size: %v\n", len(packageIDs))

	//remove irrelavent packages by file packageID
	for i, rcount, rlen := 0, 0, len(model.Artifacts); i < rlen; i++ {
		j := i - rcount
		if !contains(model.Artifacts[j].ID, packageIDs) {
			model.Artifacts = append(model.Artifacts[:j], model.Artifacts[j+1:]...)
			rcount++
		}
	}
	logger.Print(logger.DEBUG, false, "model.Artifacts size: %d\n", len(model.Artifacts))

	sbom.sbomData, err = json.Marshal(model)
	if err != nil {
		logger.Print(logger.ERROR, false, "FilterSbom: failed marshall new filter with err %v\n", err)
		return err
	}
	err = utils.SaveDataToFile(sbom.sbomData, sbom.sbomFilteredFilePath)
	if err != nil {
		logger.Print(logger.ERROR, false, "FilterSbom: failed to save filtered sbom to file with error: %v", err)
		return err
	}

	logger.Print(logger.DEBUG, false, "sbom.sbomData after filter: %s\n", string(sbom.sbomData))
	return nil
}

func (sbom *SbomObject) GetSbomFilePath() string {
	return sbom.sbomFilteredFilePath
}

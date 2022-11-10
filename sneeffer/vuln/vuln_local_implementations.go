package vuln

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
	"strconv"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/kubescape/sneeffer/internal/logger"
	"github.com/kubescape/sneeffer/sneeffer/sbom"
	"github.com/kubescape/sneeffer/sneeffer/utils"
	"github.com/xyproto/randomstring"
	"gopkg.in/yaml.v2"

	"github.com/anchore/grype/grype/presenter/models"
)

type VulnsBySeverity struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	All        int `json:"all"`
}

type VulnSummaryData struct {
	ImageCVEsNumber   VulnsBySeverity `json:"imageVulns"`
	RuntimeCVEsNumber VulnsBySeverity `json:"runtimeVulns"`
	Description       string          `json:"description"`
}

type VulnSummary struct {
	ImageName       string          `json:"imageName"`
	K8sAncestorName string          `json:"ancestorName,omitempty"`
	VulnSummaryData VulnSummaryData `json:"summary"`
}

type VulnCVEs struct {
	CVEName     string `json:"cVEName"`
	CVESeverity string `json:"cVESeverity"`
}

type VulnDetailed struct {
	ImageName       string     `json:"imageName"`
	K8sAncestorName string     `json:"ancestorName,omitempty"`
	RelaventCVEs    []VulnCVEs `json:"relaventCVEs"`
	IrrelaventCVEs  []VulnCVEs `json:"irrelaventCVEs"`
}

type ProccesedVulnData struct {
	DataSummary  VulnSummary
	DataDetailed VulnDetailed
}

type VulnObject struct {
	imageID                string
	sbomObject             *sbom.SbomObject
	vulnCreatorPath        string
	vulnData               []byte
	vulnFilteredFilePath   string
	vulnUnFilteredFilePath string
	vulnConfigDirPath      string
	credentialslist        []types.AuthConfig
	parsedVulnData         *ProccesedVulnData
}

var mutexDBIsReady chan bool
var DBIsReady bool
var mutexVulnProcess sync.Mutex

func informDatabaseIsReadyToUse(ready bool) {
	DBIsReady = ready
	mutexDBIsReady <- ready
}

func DownloadVulnDB() error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	mutexDBIsReady = make(chan bool, 10)
	DBIsReady = false
	vulnCreatorPath, _ := os.LookupEnv("vulnCreatorPath")
	vulnConfigPath := path.Join(vulnCreatorPath, "..", ".grype", "config.yaml")

	cmd := exec.Command(vulnCreatorPath, "db", "update", "-c", vulnConfigPath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Print(logger.DEBUG, false, "start vuln db update\n")
	err := cmd.Run()
	if err != nil {
		informDatabaseIsReadyToUse(false)
		logger.Print(logger.ERROR, false, "GetImageVulnerabilities process failed with error %v, stderr: %s \nstdout:%s", err, stderr.String(), stdout.String())
		return err
	}

	logger.Print(logger.DEBUG, false, "vuln DB updated successfully\n")
	informDatabaseIsReadyToUse(true)
	return nil
}

func CreateVulnObject(credentialslist []types.AuthConfig, imageID string, sbomObject *sbom.SbomObject) *VulnObject {
	vulnCreatorPath, _ := os.LookupEnv("vulnCreatorPath")
	innerDataDirPath, _ := os.LookupEnv("innerDataDirPath")

	imageIDPath := strings.ReplaceAll(imageID, "/", "_")

	return &VulnObject{
		imageID:                imageID,
		sbomObject:             sbomObject,
		vulnCreatorPath:        vulnCreatorPath,
		vulnFilteredFilePath:   innerDataDirPath + "/vuln/" + imageIDPath + "-filtered",
		vulnUnFilteredFilePath: innerDataDirPath + "/vuln/" + imageIDPath + "-unfiltered",
		credentialslist:        credentialslist,
		vulnConfigDirPath:      filepath.Dir(vulnCreatorPath),
	}
}

func (vuln *VulnObject) copyFileData(anchoreConfigPath string) error {
	source, err := os.Open(path.Join(vuln.vulnConfigDirPath, ".grype", "config.yaml"))
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(anchoreConfigPath)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return err
}

func (vuln *VulnObject) addCredentialsToAnchoreConfigurationFile(configFilePath string, cred types.AuthConfig) error {
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

func (vuln *VulnObject) GetImageVulnerabilities(errChan chan error) bool {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	if !DBIsReady {
		ready := <-mutexDBIsReady
		if ready {
			mutexDBIsReady <- true
		} else {
			return false
		}
	}

	configFileName := randomstring.HumanFriendlyEnglishString(rand.Intn(100)) + ".yaml"
	anchoreConfigPath := path.Join(vuln.vulnConfigDirPath, ".grype", configFileName)
	err := vuln.copyFileData(anchoreConfigPath)
	if err != nil {
		logger.Print(logger.ERROR, false, "failed to copy default file config to %v with err %v\n", anchoreConfigPath, err)
		os.Remove(anchoreConfigPath)
		return false
	}

	for i := 0; i != len(vuln.credentialslist); i++ {
		err := vuln.addCredentialsToAnchoreConfigurationFile(anchoreConfigPath, vuln.credentialslist[i])
		if err != nil {
			logger.Print(logger.ERROR, false, "failed to copy default file config to %v with err %v\n", anchoreConfigPath, err)
			os.Remove(anchoreConfigPath)
			return false
		}
	}

	cmd := exec.Command(vuln.vulnCreatorPath, vuln.imageID, "-o", "json", "-c", anchoreConfigPath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	mutexVulnProcess.Lock()
	logger.Print(logger.INFO, false, "start vuln command for image %s\n", vuln.imageID)
	logger.Print(logger.DEBUG, false, "cmd.Args %s\n", cmd.Args)
	err = cmd.Run()
	if err != nil {
		logger.Print(logger.ERROR, false, "GetImageVulnerabilities: vuln finder process fail with error %v\n", err)
		os.Remove(anchoreConfigPath)
		errChan <- fmt.Errorf("GetImageVulnerabilities process failed with error %v, stderr: %s \nstdout:%s", err, stderr.String(), stdout.String())
		return false
	}
	mutexVulnProcess.Unlock()

	vuln.vulnData = stdout.Bytes()
	err = utils.SaveDataToFile(vuln.vulnData, vuln.vulnUnFilteredFilePath)
	if err != nil {
		logger.Print(logger.ERROR, false, "GetFilterVulnerabilities: Error: failed to save filtered vuln to file with error: %v", err)
		os.Remove(anchoreConfigPath)
		errChan <- fmt.Errorf("GetImageVulnerabilities failed with error %v", err)
		return false
	}
	logger.Print(logger.INFO, false, "the unfiltered vuln getting finished successesfully for image %s\n", vuln.imageID)
	os.Remove(anchoreConfigPath)
	errChan <- nil
	return true
}

func (vuln *VulnObject) GetFilterVulnerabilities() error {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	if !DBIsReady {
		ready := <-mutexDBIsReady
		if ready {
			mutexDBIsReady <- true
		} else {
			return fmt.Errorf("GetFilterVulnerabilities: DB download failed")
		}
	}

	cmd := exec.Command(vuln.vulnCreatorPath, "sbom:"+vuln.sbomObject.GetSbomFilePath(), "-o", "json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	mutexVulnProcess.Lock()
	logger.Print(logger.INFO, false, "start vuln command for filtered vulnerabilities %s\n", vuln.imageID)
	logger.Print(logger.DEBUG, false, "cmd.Args %s\n", cmd.Args)
	err := cmd.Run()
	if err != nil {
		logger.Print(logger.ERROR, false, "GetFilterVulnerabilities: vuln finder process fail with error %v\n", err)
		logger.Print(logger.ERROR, false, "GetFilterVulnerabilities: vuln finder process stderr: \n")
		logger.Print(logger.ERROR, false, "%s\n", stderr.String())
		return err
	}
	mutexVulnProcess.Unlock()

	vuln.vulnData = stdout.Bytes()
	logger.Print(logger.INFO, false, "the filtered vuln getting finished successesfully for image %s\n", vuln.imageID)

	err = utils.SaveDataToFile(vuln.vulnData, vuln.vulnFilteredFilePath)
	if err != nil {
		logger.Print(logger.ERROR, false, "GetFilterVulnerabilities: Error: failed to save filtered vuln to file with error: %v", err)
		return err
	}

	err = vuln.parseVulnFinalData()
	if err != nil {
		logger.Print(logger.ERROR, false, "GetFilterVulnerabilities: Error: failed to parse vuln final data error: %v", err)
		return err
	}

	return nil
}

func contains(needle string, haystack []VulnCVEs) bool {
	for i := range haystack {
		if haystack[i].CVEName == needle {
			return true
		}
	}
	return false
}

func (vuln *VulnObject) convertToFinalDataStructures(vulnUnfilteredData, vulnFilteredData *models.Document) error {
	proccesedVulnData := ProccesedVulnData{}
	relventBySeverity := map[string]int{
		"Critical":   0,
		"High":       0,
		"Medium":     0,
		"Low":        0,
		"Negligible": 0,
	}
	relaventIdx := 0

	irrelventBySeverity := map[string]int{
		"Critical":   0,
		"High":       0,
		"Medium":     0,
		"Low":        0,
		"Negligible": 0,
	}
	allCVEsIdx := 0

	proccesedVulnData.DataDetailed.ImageName = vuln.imageID
	proccesedVulnData.DataDetailed.K8sAncestorName = ""
	proccesedVulnData.DataSummary.ImageName = vuln.imageID
	proccesedVulnData.DataSummary.K8sAncestorName = ""
	for i := range vulnFilteredData.Matches {
		CVEName := vulnFilteredData.Matches[i].Vulnerability.VulnerabilityMetadata.ID
		CVESeverity := vulnFilteredData.Matches[i].Vulnerability.VulnerabilityMetadata.Severity
		relventBySeverity[CVESeverity] = relventBySeverity[CVESeverity] + 1
		proccesedVulnData.DataDetailed.RelaventCVEs = append(proccesedVulnData.DataDetailed.RelaventCVEs, VulnCVEs{CVEName: CVEName, CVESeverity: CVESeverity})
		relaventIdx++
	}
	for i := range vulnUnfilteredData.Matches {
		CVEName := vulnUnfilteredData.Matches[i].Vulnerability.VulnerabilityMetadata.ID
		CVESeverity := vulnUnfilteredData.Matches[i].Vulnerability.VulnerabilityMetadata.Severity
		if !contains(vulnUnfilteredData.Matches[i].Vulnerability.VulnerabilityMetadata.ID, proccesedVulnData.DataDetailed.IrrelaventCVEs) {
			proccesedVulnData.DataDetailed.IrrelaventCVEs = append(proccesedVulnData.DataDetailed.IrrelaventCVEs, VulnCVEs{CVEName: CVEName, CVESeverity: CVESeverity})
		}
		irrelventBySeverity[CVESeverity] = irrelventBySeverity[CVESeverity] + 1
		allCVEsIdx++
	}
	proccesedVulnData.DataSummary.VulnSummaryData.ImageCVEsNumber.Critical = irrelventBySeverity["Critical"]
	proccesedVulnData.DataSummary.VulnSummaryData.ImageCVEsNumber.High = irrelventBySeverity["High"]
	proccesedVulnData.DataSummary.VulnSummaryData.ImageCVEsNumber.Medium = irrelventBySeverity["Medium"]
	proccesedVulnData.DataSummary.VulnSummaryData.ImageCVEsNumber.Low = irrelventBySeverity["Low"]
	proccesedVulnData.DataSummary.VulnSummaryData.ImageCVEsNumber.Negligible = irrelventBySeverity["Negligible"]
	proccesedVulnData.DataSummary.VulnSummaryData.ImageCVEsNumber.All = allCVEsIdx

	proccesedVulnData.DataSummary.VulnSummaryData.RuntimeCVEsNumber.Critical = relventBySeverity["Critical"]
	proccesedVulnData.DataSummary.VulnSummaryData.RuntimeCVEsNumber.High = relventBySeverity["High"]
	proccesedVulnData.DataSummary.VulnSummaryData.RuntimeCVEsNumber.Medium = relventBySeverity["Medium"]
	proccesedVulnData.DataSummary.VulnSummaryData.RuntimeCVEsNumber.Low = relventBySeverity["Low"]
	proccesedVulnData.DataSummary.VulnSummaryData.RuntimeCVEsNumber.Negligible = relventBySeverity["Negligible"]
	proccesedVulnData.DataSummary.VulnSummaryData.RuntimeCVEsNumber.All = relaventIdx
	proccesedVulnData.DataSummary.VulnSummaryData.Description = "Wow!! there are only " + strconv.Itoa(relaventIdx) + " relavent vulnerebilities out of " + strconv.Itoa(allCVEsIdx) + " in this image"

	vuln.parsedVulnData = &proccesedVulnData
	return nil
}

func (vuln *VulnObject) parseVulnFinalData() error {
	vulnUnfilteredData := &models.Document{}
	vulnFilteredData := &models.Document{}

	vulnUnfilteredBytes, err := utils.FileBytes(vuln.vulnUnFilteredFilePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(vulnUnfilteredBytes, vulnUnfilteredData)
	if err != nil {
		return err
	}

	vulnFilteredBytes, err := utils.FileBytes(vuln.vulnFilteredFilePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(vulnFilteredBytes, vulnFilteredData)
	if err != nil {
		return err
	}

	err = vuln.convertToFinalDataStructures(vulnUnfilteredData, vulnFilteredData)
	if err != nil {
		return err
	}

	return nil
}

func (vuln *VulnObject) GetProcessedData() *ProccesedVulnData {
	return vuln.parsedVulnData
}

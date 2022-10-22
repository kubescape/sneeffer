package vuln

import (
	"armo_sneeffer/internal/logger"
	"armo_sneeffer/sneeffer/sbom"
	"armo_sneeffer/sneeffer/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"

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
	parsedVulnData         *ProccesedVulnData
}

func CreateVulnObject(imageID string, sbomObject *sbom.SbomObject) *VulnObject {
	vulnCreatorPath, _ := os.LookupEnv("vulnCreatorPath")
	innerDataDirPath, _ := os.LookupEnv("innerDataDirPath")

	return &VulnObject{
		imageID:                imageID,
		sbomObject:             sbomObject,
		vulnCreatorPath:        vulnCreatorPath,
		vulnFilteredFilePath:   innerDataDirPath + "/vuln/" + imageID + "-filtered",
		vulnUnFilteredFilePath: innerDataDirPath + "/vuln/" + imageID + "-unfiltered",
	}
}

func (vuln *VulnObject) GetImageVulnerabilities(errChan chan error) bool {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	cmd := exec.Command(vuln.vulnCreatorPath, vuln.imageID, "-o", "json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Print(logger.INFO, false, "start vuln command for image %s\n", vuln.imageID)
	logger.Print(logger.DEBUG, false, "cmd.Args %s\n", cmd.Args)
	err := cmd.Run()
	if err != nil {
		logger.Print(logger.ERROR, false, "GetImageVulnerabilities: vuln finder process fail with error %v\n", err)
		errChan <- fmt.Errorf("GetImageVulnerabilities process failed with error %v, stderr: %s", err, stderr.String())
		return false
	}
	vuln.vulnData = stdout.Bytes()
	err = utils.SaveDataToFile(vuln.vulnData, vuln.vulnUnFilteredFilePath)
	if err != nil {
		logger.Print(logger.ERROR, false, "GetFilterVulnerabilities: Error: failed to save filtered vuln to file with error: %v", err)
		errChan <- fmt.Errorf("GetImageVulnerabilities failed with error %v", err)
		return false
	}
	logger.Print(logger.INFO, false, "the unfiltered vuln getting finished successesfully for image %s\n", vuln.imageID)
	errChan <- nil
	return true
}

func (vuln *VulnObject) GetFilterVulnerabilities() error {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	cmd := exec.Command(vuln.vulnCreatorPath, "sbom:"+vuln.sbomObject.GetSbomFilePath(), "-o", "json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Print(logger.INFO, false, "start vuln command for filtered vulnerabilities %s\n", vuln.imageID)
	logger.Print(logger.DEBUG, false, "cmd.Args %s\n", cmd.Args)
	err := cmd.Run()
	if err != nil {
		logger.Print(logger.ERROR, false, "GetFilterVulnerabilities: vuln finder process fail with error %v\n", err)
		logger.Print(logger.ERROR, false, "GetFilterVulnerabilities: vuln finder process stderr: \n")
		logger.Print(logger.ERROR, false, "%s\n", stderr.String())
		return err
	}
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

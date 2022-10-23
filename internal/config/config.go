package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/kubescape/sneeffer/internal/logger"
)

var manadatoryConfigurationVars []string
var innerDirectoriesPath []string

func init() {
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "kernelObjPath")
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "snifferEngineLoaderPath")
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "sbomCreatorPath")
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "vulnCreatorPath")
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "innerDataDirPath")
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "crdFullDetailedPath")
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "crdVulnSummaryPath")
	manadatoryConfigurationVars = append(manadatoryConfigurationVars, "myNode")
	innerDirectoriesPath = append(innerDirectoriesPath, "/sbom")
	innerDirectoriesPath = append(innerDirectoriesPath, "/vuln")
}

func parseConfigurationFile(configurationFilePath string) error {
	readFile, err := os.Open(configurationFilePath)
	if err != nil {
		return err
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		line := fileScanner.Text()
		confData := strings.Split(line, "=")
		if confData[0] == line {
			log.Printf("ParseConfigurationFile: seperator = is not exist in configuration file line: %s\n", line)
			continue
		}
		if os.Setenv(confData[0], confData[1]) != nil {
			log.Printf("ParseConfigurationFile: fail to set env %s=%s", confData[0], confData[1])
		}
	}
	readFile.Close()
	return nil
}

func validateMandatoryConfigurationn() error {
	for i := range manadatoryConfigurationVars {
		if _, exist := os.LookupEnv(manadatoryConfigurationVars[i]); !exist {
			return fmt.Errorf("validateMandatoryConfigurationn: %s not exist", manadatoryConfigurationVars[i])
		}
	}
	return nil
}

func createInnerDirectories() error {
	innerDataDirPath, exist := os.LookupEnv("innerDataDirPath")
	if !exist {
		return fmt.Errorf("error: createInnerDirectories: filed to find env var innerDataDirPath")
	}

	for i := range innerDirectoriesPath {
		err := os.Mkdir(innerDataDirPath+innerDirectoriesPath[i], 0600)
		if err != nil {
			if !strings.Contains(err.Error(), "file exists") {
				return fmt.Errorf("error: createInnerDirectories: fail to create directory %s", innerDataDirPath+innerDirectoriesPath[i])
			}
		}
	}

	return nil
}

func loggerConfig() {
	verbose, exist := os.LookupEnv("loggerVerbose")
	if !exist {
		log.Printf("loggerVerbose is not set in the configuration file, we will print warning logs and above\n")
		verbose = "WARNING"
	}
	logger.ConfigLogger(verbose, "")
}

func afterConfigurationParserActions() error {
	err := createInnerDirectories()
	if err != nil {
		return err
	}
	loggerConfig()
	return nil
}

func ParseConfiguration() error {
	configurationFilePath, exist := os.LookupEnv("SNEEFFER_CONF_FILE_PATH")
	if !exist {
		return fmt.Errorf("env var SNEEFFER_CONF_FILE_PATH is not exist")
	}

	err := parseConfigurationFile(configurationFilePath)
	if err != nil {
		return err
	}

	err = validateMandatoryConfigurationn()
	if err != nil {
		return err
	}

	err = afterConfigurationParserActions()
	if err != nil {
		return err
	}

	return nil
}

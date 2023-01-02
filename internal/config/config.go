package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/kubescape/sneeffer/internal/logger"
)

const (
	RELAVENT_CVES_SERVICE       = "RELAVENT_CVES_SERVICE"
	CONTAINER_PROFILING_SERVICE = "CONTAINER_PROFILING_SERVICE"
)

var myContainerID string

var sycscallFilterForRelaventCVES []string
var sycscallFilterForContainerProfiling []string

var manadatoryConfigurationVars []string
var innerDirectoriesPath []string

var relaventCVEService bool
var containerProfilingService bool

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
	sycscallFilterForRelaventCVES = append(sycscallFilterForRelaventCVES, []string{"execve", "execveat", "open", "openat"}...)
	containerProfilingService = false
	relaventCVEService = false
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

func servicesConfig() error {
	serviceExist := false

	val, exist := os.LookupEnv("enableRelaventCVEsService")
	if exist {
		if val == "true" || val == "True" {
			relaventCVEService = true
			serviceExist = true
			logger.Print(logger.INFO, false, "sneeffer service find relavent CVEs is enabled\n")
		}
	}
	val, exist = os.LookupEnv("enableContainerProfilingService")
	if exist {
		if val == "true" || val == "True" {
			containerProfilingService = true
			serviceExist = true
			logger.Print(logger.INFO, false, "sneeffer service container profiling is enabled\n")
		}
	}
	if !serviceExist {
		return fmt.Errorf("no service is configured to use, please look in the configuration file that one of the services mark as true or True")
	}
	return nil
}

func afterConfigurationParserActions() error {
	err := createInnerDirectories()
	if err != nil {
		return err
	}
	loggerConfig()
	return servicesConfig()
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

func GetSyscallFilter() []string {
	if IsContainerProfilingServiceEnabled() {
		return sycscallFilterForContainerProfiling
	}
	return sycscallFilterForRelaventCVES
}

func IsRelaventCVEServiceEnabled() bool {
	return relaventCVEService
}

func IsContainerProfilingServiceEnabled() bool {
	return containerProfilingService
}

func SetMyContainerID(ContainerID string) {
	myContainerID = ContainerID
}

func GetMyContainerID() string {
	return myContainerID
}

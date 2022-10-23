package sniffer_engine

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/kubescape/sneeffer/internal/logger"
)

type SnifferEngine struct {
	kernelObjPath       string
	syscallFilterString string
	includeHost         bool
	sniffMainThreadOnly bool
	containerID         string
}

func createSyscallFilterString(syscallFilter []string) string {
	filterString := ""

	for i := range syscallFilter {
		filterString += "evt.type=" + syscallFilter[i]
		if i < len(syscallFilter)-1 {
			filterString += " or "
		}
	}
	return filterString
}

func CreateSnifferEngine(syscallFilter []string, includeHost bool, sniffMainThreadOnly bool, containerID string) *SnifferEngine {
	kernelObjPath := os.Getenv("kernelObjPath")
	syscallFilterString := createSyscallFilterString(syscallFilter)

	return &SnifferEngine{
		kernelObjPath:       kernelObjPath,
		syscallFilterString: syscallFilterString,
		includeHost:         includeHost,
		sniffMainThreadOnly: sniffMainThreadOnly,
		containerID:         containerID,
	}
}

func (snifferEngine *SnifferEngine) snifferEngineCMDWithParams() []string {
	var fullSnifferEngineCMD []string

	if snifferEngine.syscallFilterString != "" {
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-f")
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, snifferEngine.syscallFilterString)
	}
	if snifferEngine.includeHost {
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-o")
	}
	if snifferEngine.sniffMainThreadOnly {
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-m")
	}
	if snifferEngine.containerID != "" {
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-c")
		fullSnifferEngineCMD = append(fullSnifferEngineCMD, snifferEngine.containerID)
	}
	fullSnifferEngineCMD = append(fullSnifferEngineCMD, "-e")
	fullSnifferEngineCMD = append(fullSnifferEngineCMD, snifferEngine.kernelObjPath)

	return fullSnifferEngineCMD
}

func (snifferEngine *SnifferEngine) StartSnifferEngine() (io.ReadCloser, int, error, *exec.Cmd) {
	snifferEngineLoaderPath := os.Getenv("snifferEngineLoaderPath")
	if snifferEngineLoaderPath == "" {
		return nil, -1, fmt.Errorf("startSnifferEngine: the env var snifferEngineLoaderPath is not set"), nil
	}

	fullSnifferEngineCMD := snifferEngine.snifferEngineCMDWithParams()
	cmd := exec.Command(snifferEngineLoaderPath, fullSnifferEngineCMD...)
	logger.Print(logger.DEBUG, false, "cmd.Args %v", cmd.Args)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, -1, err, nil
	}
	err = cmd.Start()
	if err != nil {
		logger.Print(logger.ERROR, false, "StartSnifferEngine: fail with err %v\n", err)
		return nil, -1, err, nil
	}
	return stdout, cmd.Process.Pid, nil, cmd
}

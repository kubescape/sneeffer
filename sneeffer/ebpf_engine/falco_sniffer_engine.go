package ebpf_engine

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kubescape/sneeffer/internal/logger"

	"github.com/kubescape/sneeffer/sneeffer/accumulator_data_structure"
)

type FalcoEbpfEngineEngine struct {
	kernelObjPath       string
	syscallFilterString string
	includeHost         bool
	sniffMainThreadOnly bool
	containerID         string
	reader              io.ReadCloser
	pid                 int
	cmd                 *exec.Cmd
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

func CreateFalcoEbpfEngine(syscallFilter []string, includeHost bool, sniffMainThreadOnly bool, containerID string) *FalcoEbpfEngineEngine {
	kernelObjPath := os.Getenv("kernelObjPath")
	syscallFilterString := createSyscallFilterString(syscallFilter)

	return &FalcoEbpfEngineEngine{
		kernelObjPath:       kernelObjPath,
		syscallFilterString: syscallFilterString,
		includeHost:         includeHost,
		sniffMainThreadOnly: sniffMainThreadOnly,
		containerID:         containerID,
	}
}

func (FalcoEbpfEngineEngine *FalcoEbpfEngineEngine) ebpfEngineCMDWithParams() []string {
	var fullEbpfEngineCMD []string

	if FalcoEbpfEngineEngine.syscallFilterString != "" {
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-f")
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, FalcoEbpfEngineEngine.syscallFilterString)
	}
	if FalcoEbpfEngineEngine.includeHost {
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-o")
	}
	if FalcoEbpfEngineEngine.sniffMainThreadOnly {
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-m")
	}
	if FalcoEbpfEngineEngine.containerID != "" {
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-c")
		fullEbpfEngineCMD = append(fullEbpfEngineCMD, FalcoEbpfEngineEngine.containerID)
	}
	fullEbpfEngineCMD = append(fullEbpfEngineCMD, "-e")
	fullEbpfEngineCMD = append(fullEbpfEngineCMD, FalcoEbpfEngineEngine.kernelObjPath)

	return fullEbpfEngineCMD
}

func (FalcoEbpfEngineEngine *FalcoEbpfEngineEngine) StartEbpfEngine() error {
	snifferEngineLoaderPath := os.Getenv("snifferEngineLoaderPath")
	if snifferEngineLoaderPath == "" {
		return fmt.Errorf("StartEbpfEngine: the env var snifferEngineLoaderPath is not set")
	}

	fullEbpfEngineCMD := FalcoEbpfEngineEngine.ebpfEngineCMDWithParams()
	cmd := exec.Command(snifferEngineLoaderPath, fullEbpfEngineCMD...)
	logger.Print(logger.DEBUG, false, "cmd.Args %v", cmd.Args)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		logger.Print(logger.DEBUG, false, "StartEbpfEngine: fail with err %v", err)
		return err
	}
	FalcoEbpfEngineEngine.cmd = cmd
	FalcoEbpfEngineEngine.reader = stdout
	FalcoEbpfEngineEngine.pid = cmd.Process.Pid
	return nil
}

func convertStrigTimeToTimeOBJ(Timestamp string) (*time.Time, error) {
	dateAndTime := strings.Split(Timestamp, "T")
	date := strings.Split(dateAndTime[0], "-")
	tm := strings.Split(dateAndTime[1], ":")

	year, err := strconv.Atoi(date[0])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v", err)
		return nil, err
	}
	month, err := strconv.Atoi(date[1])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v", err)
		return nil, err
	}
	day, err := strconv.Atoi(date[2])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v", err)
		return nil, err
	}

	hour, err := strconv.Atoi(tm[0])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v", err)
		return nil, err
	}
	minute, err := strconv.Atoi(tm[1])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v", err)
		return nil, err
	}
	seconds := strings.Split(tm[2], "+")
	secs := strings.Split(seconds[0], ".")

	sec, err := strconv.Atoi(secs[0])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v", err)
		return nil, err
	}

	nsec, err := strconv.Atoi(secs[1])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v", err)
		return nil, err
	}

	t := time.Date(year, time.Month(month), day, hour, minute, sec, nsec, time.Now().Location())
	return &t, nil
}

func parseLine(line string) (*accumulator_data_structure.MetadataAccumulator, error) {
	if strings.Contains(line, "drop event occured") {
		return &accumulator_data_structure.MetadataAccumulator{
			Cmd: "drop event occured\n",
		}, nil
	}
	lineParts := strings.Split(line, "]::[")
	if len(lineParts) != 8 {
		logger.Print(logger.ERROR, false, "we have got unknown line format, line is %s", line)
		return nil, fmt.Errorf("we have got unknown line format, line is %s", line)
	}
	Timestamp, err := convertStrigTimeToTimeOBJ(lineParts[0])
	if err != nil {
		logger.Print(logger.ERROR, false, "parseLine Timestamp fail line is %s err %v", line)
		return nil, fmt.Errorf("parseLine Timestamp fail line is %s, err %v", line, err)
	}
	return &accumulator_data_structure.MetadataAccumulator{
		Timestamp:       *Timestamp,
		ContainerID:     lineParts[1],
		SyscallCategory: lineParts[2],
		Ppid:            lineParts[3],
		Pid:             lineParts[4],
		SyscallType:     lineParts[5],
		Exe:             lineParts[6],
		Cmd:             lineParts[7],
	}, nil
}

func (FalcoEbpfEngineEngine *FalcoEbpfEngineEngine) GetEbpfEngineData(ebpfEngineDataChannel chan *accumulator_data_structure.MetadataAccumulator) {
	for {
		scanner := bufio.NewScanner(FalcoEbpfEngineEngine.reader)
		for scanner.Scan() {
			fullLine := scanner.Text()
			if fullLine != "" {
				data, err := parseLine(fullLine)
				if err != nil {
					continue
				}
				ebpfEngineDataChannel <- data
			}
		}
	}
}

func (FalcoEbpfEngineEngine *FalcoEbpfEngineEngine) GetEbpfEngineError() error {
	return FalcoEbpfEngineEngine.cmd.Wait()
}

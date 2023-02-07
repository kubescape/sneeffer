package ebpf_engine

import (
	"strconv"
	"time"

	"github.com/kubescape/sneeffer/sneeffer/accumulator_data_structure"

	"github.com/slashben/kubescape-ebpf/core/common"
	fileaccessmonitor "github.com/slashben/kubescape-ebpf/core/file-access-monitor"
)

type ciliumEbpfEngineClient struct {
	eventChannel chan fileaccessmonitor.FileActivityEvent
}

type CiliumEbpfEngine struct {
	ebpfEngineClient           *fileaccessmonitor.FileActivityMonitor
	ciliumEbpfEngineClientData ciliumEbpfEngineClient
}

func CreateCiliumEbpfEngine() *CiliumEbpfEngine {
	client := ciliumEbpfEngineClient{
		eventChannel: make(chan fileaccessmonitor.FileActivityEvent),
	}
	return &CiliumEbpfEngine{
		ebpfEngineClient:           fileaccessmonitor.CreateFileActivityMonitor(&client),
		ciliumEbpfEngineClientData: client,
	}
}

func (CiliumEbpfEngine *CiliumEbpfEngine) StartEbpfEngine() error {
	CiliumEbpfEngine.ebpfEngineClient.Start()
	return nil
}

func parseTime(t uint64) (*time.Time, error) {
	time_str, err := strconv.ParseInt(strconv.FormatUint(t, 10), 10, 64)
	if err != nil {
		return nil, err
	}
	tm := time.Unix(time_str, 0)
	return &tm, nil
}

func parseEvent(event fileaccessmonitor.FileActivityEvent) (*accumulator_data_structure.MetadataAccumulator, error) {
	cid, err := common.GetContainerIdForNsMntId(event.NsMntId)
	if err != nil {
		return nil, err
	}

	t, err := parseTime(event.Timestamp)
	if err != nil {
		return nil, err
	}

	// logger.Print(logger.INFO, false, "cid %s\n", cid)
	return &accumulator_data_structure.MetadataAccumulator{
		Timestamp:       *t,
		ContainerID:     cid[:12],
		SyscallCategory: "",
		SyscallType:     event.File,
		Ppid:            "",
		Pid:             strconv.Itoa(event.Pid),
		Exe:             event.Comm,
		Cmd:             "",
	}, nil
}

func (CiliumEbpfEngine *CiliumEbpfEngine) GetEbpfEngineData(ebpfEngineDataChannel chan *accumulator_data_structure.MetadataAccumulator) {
	for {
		data, err := parseEvent(<-CiliumEbpfEngine.ciliumEbpfEngineClientData.eventChannel)
		if err != nil {
			continue
		}
		ebpfEngineDataChannel <- data
	}
}

func (client *ciliumEbpfEngineClient) Notify(event fileaccessmonitor.FileActivityEvent) {
	client.eventChannel <- event
}

func (CiliumEbpfEngine *CiliumEbpfEngine) GetEbpfEngineError() error {
	return nil
}

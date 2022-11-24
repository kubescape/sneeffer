package aggregator

import (
	"strings"

	"github.com/kubescape/sneeffer/internal/logger"
	"github.com/kubescape/sneeffer/sneeffer/accumulator"
	"github.com/kubescape/sneeffer/sneeffer/utils"
)

var scedulingSyscalls []string

func init() {
	scedulingSyscalls = append(scedulingSyscalls, []string{"nice", "sched_setscheduler", "sched_getscheduler", "sched_setparam", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "sched_setaffinity", "sched_getaffinity", "sched_yield"}...)
}

type Aggregator struct {
	containerID         string
	stopAggregate       bool
	aggregationData     []accumulator.MetadataAccumulator
	aggregationDataChan chan accumulator.MetadataAccumulator
	ppid_to_pid         map[string][]string
	containerAccumuator *accumulator.ContainerAccumulator
	cacheAccumuator     *accumulator.CacheAccumulator
	containerStartTime  interface{}
	errChan             chan error
}

func CreateAggregator(containerID string, containerStartTime interface{}) *Aggregator {
	return &Aggregator{
		containerID:         containerID,
		stopAggregate:       false,
		aggregationData:     make([]accumulator.MetadataAccumulator, 0),
		aggregationDataChan: make(chan accumulator.MetadataAccumulator),
		ppid_to_pid:         make(map[string][]string),
		containerAccumuator: nil,
		cacheAccumuator:     accumulator.GetCacheAccumaltor(),
		containerStartTime:  containerStartTime,
	}
}

func (aggregator *Aggregator) collectDataFromContainerAccumulator() {
	for {
		newData := <-aggregator.aggregationDataChan
		aggregator.aggregationData = append(aggregator.aggregationData, newData)
	}
}

func (aggregator *Aggregator) aggregateFromCacheAccumulator() {
	aggregator.cacheAccumuator.AccumulatorByContainerID(&aggregator.aggregationData, aggregator.containerID, aggregator.containerStartTime)
	// logger.Print(logger.DEBUG, false, "aggregator.aggregationData for containerID %s:\n%v\n", aggregator.containerID, aggregator.aggregationData)
}

func (aggregator *Aggregator) StartAggregate(errChan chan error, resourceName string, syscallFilter []string, includeHost bool, sniffMainThreadOnly bool) error {
	aggregator.errChan = errChan
	aggregator.containerAccumuator = accumulator.CreateContainerAccumulator(aggregator.containerID, aggregator.aggregationDataChan)
	go aggregator.containerAccumuator.StartContainerAccumalator(errChan, resourceName, syscallFilter, includeHost, sniffMainThreadOnly)
	go aggregator.collectDataFromContainerAccumulator()
	aggregator.aggregateFromCacheAccumulator()
	return nil
}

func (aggregator *Aggregator) StopAggregate() error {
	aggregator.containerAccumuator.StopWatching(aggregator.errChan)
	return nil
}

func parseFileName(snifferData accumulator.MetadataAccumulator) string {
	fileName := ""
	switch snifferData.SyscallCategory {
	case "CAT=PROCESS":
		if strings.HasPrefix(snifferData.SyscallType, "TYPE=execve(") {
			fileName = utils.Between(snifferData.SyscallType, "filename: ", ")")
		} else if strings.HasPrefix(snifferData.SyscallType, "TYPE=execve(") {
			fileName = utils.Between(snifferData.SyscallType, "dirfd: <f>", ", pathname:")
		}
	case "CAT=FILE":
		if strings.HasPrefix(snifferData.SyscallType, "TYPE=openat(") {
			fileName = utils.Between(snifferData.SyscallType, "name: ", ", flags")
		} else if strings.HasPrefix(snifferData.SyscallType, "TYPE=open(") {
			fileName = utils.Between(snifferData.SyscallType, "name: ", ", flags")
		}
	}
	return fileName
}

func parseSyscallName(snifferData accumulator.MetadataAccumulator) string {
	syscallName := utils.Between(snifferData.SyscallType, "TYPE=", "(")
	if strings.Contains(syscallName, "UNKNOWN 0") {
		if strings.Contains(snifferData.SyscallType, "(ID: ") {
			return utils.Between(snifferData.SyscallType, "(ID: ", ",")
		}
	} else if strings.Contains(syscallName, "UNKNOWN 1") {
		if strings.Contains(snifferData.SyscallType, "(ID: ") {
			return utils.Between(snifferData.SyscallType, "(ID: ", ")]")
		}
	}
	if snifferData.SyscallCategory == "CAT=SCHEDULER" {
		return ""
	}
	return syscallName
}

func (aggregator *Aggregator) GetContainerRealtimeFileList() []string {
	var snifferRealtimeFileList []string

	logger.Print(logger.DEBUG, false, "GetContainerRealtimeFileList: aggregator.aggregationData %d\n", len(aggregator.aggregationData))
	for i := range aggregator.aggregationData {
		fileName := parseFileName(aggregator.aggregationData[i])
		if fileName != "" {
			snifferRealtimeFileList = append(snifferRealtimeFileList, fileName)
		}
	}

	logger.Print(logger.DEBUG, false, "GetContainerRealtimeFileList: list size %d\n", len(snifferRealtimeFileList))
	logger.Print(logger.DEBUG, false, "GetContainerRealtimeFileList: list %v\n", snifferRealtimeFileList)
	return snifferRealtimeFileList
}

func addSchedulingSyscalls(snifferRealtimeSyscallList []string) []string {
	snifferRealtimeSyscallList = append(snifferRealtimeSyscallList, scedulingSyscalls...)
	return snifferRealtimeSyscallList
}

func contains(needle string, haystack []string) bool {
	for i := range haystack {
		if haystack[i] == needle {
			return true
		}
	}
	return false
}

func (aggregator *Aggregator) GetContainerRealtimeSyscalls() []string {
	var snifferRealtimeSyscallList []string

	logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData list size %d\n", len(aggregator.aggregationData))
	logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData list %v\n", aggregator.aggregationData)
	for i := range aggregator.aggregationData {
		syscallName := parseSyscallName(aggregator.aggregationData[i])
		if syscallName != "" && !contains(syscallName, snifferRealtimeSyscallList) {
			snifferRealtimeSyscallList = append(snifferRealtimeSyscallList, syscallName)
		}
	}
	snifferRealtimeSyscallList = addSchedulingSyscalls(snifferRealtimeSyscallList)

	logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: list size %d\n", len(snifferRealtimeSyscallList))
	logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: list %v\n", snifferRealtimeSyscallList)
	return snifferRealtimeSyscallList
}

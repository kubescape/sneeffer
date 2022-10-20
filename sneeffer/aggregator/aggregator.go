package aggregator

import (
	"armo_sneeffer/internal/logger"
	"armo_sneeffer/sneeffer/accumulator"
	"strings"
)

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

func between(value string, a string, b string) string {
	// Get substring between two strings.
	posFirst := strings.Index(value, a)
	if posFirst == -1 {
		return ""
	}
	posLast := strings.Index(value, b)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(a)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}

func parseFileName(snifferData accumulator.MetadataAccumulator) string {
	fileName := ""
	switch snifferData.SyscallCategory {
	case "CAT=PROCESS":
		if strings.HasPrefix(snifferData.SyscallType, "TYPE=execve(") {
			fileName = between(snifferData.SyscallType, "filename: ", ")")
		}
	case "CAT=FILE":
		if strings.HasPrefix(snifferData.SyscallType, "TYPE=openat(") {
			fileName = between(snifferData.SyscallType, "name: ", ", flags")
		}
	default:
		logger.Print(logger.ERROR, false, "parseFileName: unknown SyscallCategory\n")
	}
	return fileName
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
	return snifferRealtimeFileList
}

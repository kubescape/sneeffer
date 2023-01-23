package aggregator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/sneeffer/internal/config"
	"github.com/kubescape/sneeffer/internal/logger"
	"github.com/kubescape/sneeffer/sneeffer/accumulator"
	"github.com/kubescape/sneeffer/sneeffer/utils"
)

// unknownSyscall is list of syscall that our ebpf
var unknownSyscall []string
var duplicateSyscall map[string]string

func init() {
	unknownSyscall = append(unknownSyscall, []string{"putpmsg", "afs_syscall", "tuxcall", "security", "vserver", "ppoll", "rt_sigreturn", "_sysctl", "iopl", "ioperm", "create_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "lookup_dcookie", "mbind", "set_mempolicy", "get_mempolicy", "migrate_pages", "move_pages", "name_to_handle_at", "kcmp", "kexec_file_load", "pkey_mprotect", "pkey_alloc", "pkey_free"}...)
	duplicateSyscall = make(map[string]string)
	duplicateSyscall["pread"] = "pread64"
	duplicateSyscall["pwrite"] = "pwrite64"
	duplicateSyscall["umount"] = "umount2"
	duplicateSyscall["accept"] = "accept4"
	duplicateSyscall["signalfd"] = "signalfd4"
	duplicateSyscall["eventfd"] = "eventfd2"
	duplicateSyscall["pipe"] = "pipe2"
	duplicateSyscall["inotify_init"] = "inotify_init1"
	duplicateSyscall["prlimit"] = "prlimit64"
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

func (aggregator *Aggregator) collectDataFromContainerAccumulator(errChan chan error) {
	for {
		newData := <-aggregator.aggregationDataChan
		if newData.Cmd == "drop event occured\n" {
			aggregator.StopAggregate()
			errChan <- fmt.Errorf(newData.Cmd)
			break
		}
		aggregator.aggregationData = append(aggregator.aggregationData, newData)
	}
}

func (aggregator *Aggregator) aggregateFromCacheAccumulator() {
	aggregator.cacheAccumuator.AccumulatorByContainerID(&aggregator.aggregationData, aggregator.containerID, aggregator.containerStartTime)
}

func (aggregator *Aggregator) StartAggregate(errChan chan error) error {
	aggregator.containerAccumuator = accumulator.CreateContainerAccumulator(aggregator.containerID, aggregator.aggregationDataChan)
	go aggregator.containerAccumuator.StartContainerAccumalator()
	go aggregator.collectDataFromContainerAccumulator(errChan)
	aggregator.aggregateFromCacheAccumulator()
	return nil
}

func (aggregator *Aggregator) StopAggregate() error {
	aggregator.containerAccumuator.StopWatching()
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
	if snifferData.SyscallCategory == "CAT=SCHEDULER" {
		return ""
	}
	syscallName := utils.Between(snifferData.SyscallType, "TYPE=", "(")
	if syscallName == "unknown" {
		return ""
	}
	return syscallName
}

func (aggregator *Aggregator) GetContainerRealtimeFileList() []string {
	var snifferRealtimeFileList []string

	logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData list size %d\n", len(aggregator.aggregationData))
	logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData list %v\n", aggregator.aggregationData)
	if len(aggregator.aggregationData) > 0 {
		logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData event time range %v\n", aggregator.aggregationData[len(aggregator.aggregationData)-1].Timestamp.Sub(aggregator.aggregationData[0].Timestamp).Seconds())
	}
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

func addUnknownSyscalls(snifferRealtimeSyscallList []string) []string {
	snifferRealtimeSyscallList = append(snifferRealtimeSyscallList, unknownSyscall...)
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
	if len(aggregator.aggregationData) > 0 {
		logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: aggregator.aggregationData event time range %v\n", aggregator.aggregationData[len(aggregator.aggregationData)-1].Timestamp.Sub(aggregator.aggregationData[0].Timestamp).Seconds())
	}
	for i := range aggregator.aggregationData {
		syscallName := parseSyscallName(aggregator.aggregationData[i])
		if syscallName != "" && !contains(syscallName, snifferRealtimeSyscallList) {
			snifferRealtimeSyscallList = append(snifferRealtimeSyscallList, syscallName)
			if dupSys, ok := duplicateSyscall[syscallName]; ok {
				if !contains(dupSys, snifferRealtimeSyscallList) {
					snifferRealtimeSyscallList = append(snifferRealtimeSyscallList, dupSys)
				}
			}
		}
	}
	snifferRealtimeSyscallList = addUnknownSyscalls(snifferRealtimeSyscallList)

	sort.Strings(snifferRealtimeSyscallList)
	logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: list size %d\n", len(snifferRealtimeSyscallList))
	logger.Print(logger.DEBUG, false, "GetContainerRealtimeSyscalls: list %v\n", snifferRealtimeSyscallList)
	return snifferRealtimeSyscallList
}

func parsePeerToPeerIPs(snifferData accumulator.MetadataAccumulator, syscallName string) string {
	var clientIP string
	var serverIP string
	var port string

	if strings.Contains(snifferData.SyscallType, "->") {
		clientIP = utils.Between(snifferData.SyscallType, "tuple: ", ":")
		serverIP = utils.Between(snifferData.SyscallType, "->", ":")
		switch syscallName {
		case "connect":
			tempStr := utils.Between(snifferData.SyscallType, "->", ")")
			index := strings.Index(tempStr, ":")
			port = tempStr[index+1:]
		case "accept":
			tempStr := utils.Between(snifferData.SyscallType, "tuple: ", " queuepct")
			tempStr2 := utils.Between(tempStr, "->", ",")
			port = strings.Split(tempStr2, ":")[1]

		}
		return clientIP + "->" + serverIP + ":" + port
	}
	return ""
}

func (aggregator *Aggregator) GetNetworkMapping() map[string][]string {
	networkMap := make(map[string][]string)

	networkMap["connect"] = make([]string, 0)
	networkMap["accept"] = make([]string, 0)
	for i := range aggregator.aggregationData {
		syscallName := parseSyscallName(aggregator.aggregationData[i])
		if contains(syscallName, config.GetSycscallFilterForNetworkMonitoring()) {
			peerToPeer := parsePeerToPeerIPs(aggregator.aggregationData[i], syscallName)
			if strings.Contains(peerToPeer, "->") && !contains(peerToPeer, networkMap[syscallName]) {
				networkMap[syscallName] = append(networkMap[syscallName], peerToPeer)
			}
		}
	}

	return networkMap
}

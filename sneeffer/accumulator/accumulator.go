package accumulator

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kubescape/sneeffer/internal/logger"
	"github.com/kubescape/sneeffer/internal/sniffer_engine"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CACHE_TYPE     = 0
	CONTAINER_TYPE = 1
)

type AccumulatorInterface interface {
	accumulateSnifferData()
}

type MetadataAccumulator struct {
	Timestamp       time.Time
	ContainerID     string
	SyscallCategory string
	Ppid            string
	Pid             string
	SyscallType     string
	Exe             string
	Cmd             string
}

type CacheAccumulator struct {
	accumultorData               []map[string][]MetadataAccumulator
	firstMapKeysOfAccumultorData []string
	CacheAccumulatorSize         int
}

type ContainerAccumulator struct {
	dataChannel  chan MetadataAccumulator
	containerID  string
	watcherPID   int
	stopWatching bool
}

var cacheAccumuator *CacheAccumulator

func CreateCacheAccumulator(CacheAccumulatorSize int) *CacheAccumulator {
	cacheAccumuator = &CacheAccumulator{
		CacheAccumulatorSize:         CacheAccumulatorSize,
		accumultorData:               make([]map[string][]MetadataAccumulator, CacheAccumulatorSize),
		firstMapKeysOfAccumultorData: make([]string, CacheAccumulatorSize),
	}

	return cacheAccumuator
}

func CreateContainerAccumulator(containerID string, dataChannel chan MetadataAccumulator) *ContainerAccumulator {
	return &ContainerAccumulator{
		dataChannel:  dataChannel,
		containerID:  containerID,
		stopWatching: false,
	}
}

func convertStrigTimeToTimeOBJ(Timestamp string) (*time.Time, error) {
	dateAndTime := strings.Split(Timestamp, "T")
	date := strings.Split(dateAndTime[0], "-")
	tm := strings.Split(dateAndTime[1], ":")

	year, err := strconv.Atoi(date[0])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v\n", err)
		return nil, err
	}
	month, err := strconv.Atoi(date[1])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v\n", err)
		return nil, err
	}
	day, err := strconv.Atoi(date[2])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v\n", err)
		return nil, err
	}

	hour, err := strconv.Atoi(tm[0])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v\n", err)
		return nil, err
	}
	minute, err := strconv.Atoi(tm[1])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v\n", err)
		return nil, err
	}
	seconds := strings.Split(tm[2], "+")
	secs := strings.Split(seconds[0], ".")

	sec, err := strconv.Atoi(secs[0])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v\n", err)
		return nil, err
	}

	nsec, err := strconv.Atoi(secs[1])
	if err != nil {
		logger.Print(logger.ERROR, false, "fail strconv %v\n", err)
		return nil, err
	}

	t := time.Date(year, time.Month(month), day, hour, minute, sec, nsec, time.Now().Location())
	return &t, nil
}

func parseLine(line string) *MetadataAccumulator {
	lineParts := strings.Split(line, "]::[")
	if len(lineParts) != 8 {
		logger.Print(logger.ERROR, false, "parseLine Timestamp fail line is %s\n\n", line)
		return nil
	}
	Timestamp, err := convertStrigTimeToTimeOBJ(lineParts[0])
	if err != nil {
		logger.Print(logger.ERROR, false, "parseLine Timestamp fail line is %s, err %v\n\n", line, err)
		return nil
	}
	return &MetadataAccumulator{
		Timestamp:       *Timestamp,
		ContainerID:     lineParts[1],
		SyscallCategory: lineParts[2],
		Ppid:            lineParts[3],
		Pid:             lineParts[4],
		SyscallType:     lineParts[5],
		Exe:             lineParts[6],
		Cmd:             lineParts[7],
	}
}

// func (acc *CacheAccumulator) findIndexByTimestampWhenAccumultorDataIsFullBranchDecision(eventTime time.Time, storeTime time.Time) bool {
// 	timeDifferance := eventTime.Sub(storeTime)
// 	// logger.Print(logger.DEBUG, false, "timeDifferance %v time.Duration(acc.CacheAccumulatorSize) %v\n", timeDifferance, time.Second*time.Duration(acc.CacheAccumulatorSize))
// 	return timeDifferance > time.Second*time.Duration(acc.CacheAccumulatorSize-1) && timeDifferance < time.Second*time.Duration(acc.CacheAccumulatorSize+1)
// }

func (acc *CacheAccumulator) findIndexByTimestampWhenAccumultorDataIsFull(t time.Time) (int, bool) {
	index := 0
	minTimestamp := acc.accumultorData[0][acc.firstMapKeysOfAccumultorData[0]][0].Timestamp
	for i := range acc.accumultorData {
		if i == 0 {
			continue
		}
		if acc.accumultorData[i][acc.firstMapKeysOfAccumultorData[i]][0].Timestamp.Before(minTimestamp) {
			minTimestamp = acc.accumultorData[i][acc.firstMapKeysOfAccumultorData[i]][0].Timestamp
			index = i
		}
	}
	return index, true
}

func (acc *CacheAccumulator) findIndexByTimestamp(t time.Time) (int, bool) {
	for i := range acc.accumultorData {
		if len(acc.accumultorData[i]) == 0 {
			return i, true
		}
		firstKey := acc.firstMapKeysOfAccumultorData[i]
		if t.Sub((acc.accumultorData[i])[firstKey][0].Timestamp) < time.Second {
			return i, false
		}
	}
	index, createNewMap := acc.findIndexByTimestampWhenAccumultorDataIsFull(t)
	if index != -1 {
		return index, createNewMap
	}
	// logger.Print(logger.DEBUG, false, "findIndexByTimestamp: failed to find index, sniffer data will not saved\n")
	return -1, false
}

func (acc *CacheAccumulator) accmulateOneLine(line string) {
	metadataAcc := parseLine(line)
	if metadataAcc != nil {
		index, createNewMap := acc.findIndexByTimestamp(metadataAcc.Timestamp)
		if index == -1 {
			// logger.Print(logger.DEBUG, false, "metadataAcc %v\n", metadataAcc)
			return
		}
		if createNewMap {
			slice := make([]MetadataAccumulator, 0)
			m := make(map[string][]MetadataAccumulator)
			m[metadataAcc.ContainerID] = slice
			acc.accumultorData[index] = m
			acc.firstMapKeysOfAccumultorData[index] = metadataAcc.ContainerID
		}
		a := acc.accumultorData[index]
		a[metadataAcc.ContainerID] = append(a[metadataAcc.ContainerID], *metadataAcc)
		acc.accumultorData[index][metadataAcc.ContainerID] = append(acc.accumultorData[index][metadataAcc.ContainerID], *metadataAcc)
	}
}

func (acc *ContainerAccumulator) accmulateOneLine(line string) {
	metadataAcc := parseLine(line)
	if metadataAcc != nil {
		acc.dataChannel <- *metadataAcc
	}
}

func (acc *ContainerAccumulator) accumulateSnifferData(stdout io.ReadCloser) {
	for !acc.stopWatching {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			acc.accmulateOneLine(line)
		}
		logger.Print(logger.DEBUG, false, "ContainerAccumulator accumulateSnifferData scanner.Err(): %v\n", scanner.Err())
	}
}

func (acc *CacheAccumulator) accumulateSnifferData(stdout io.ReadCloser) {
	for {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			fullLine := scanner.Text()
			// logger.Print(logger.DEBUG, false, "fullLine %s\n", fullLine)
			acc.accmulateOneLine(fullLine)
		}
		logger.Print(logger.DEBUG, false, "CacheAccumulator accumulateSnifferData scanner.Err(): %v\n", scanner.Err())
		// if scanner.Err()
	}
}

func waitToProcessErrCode(cmd *exec.Cmd, errChan chan error) {
	errChan <- cmd.Wait()
}

func (acc *CacheAccumulator) StartCacheAccumalator(errChan chan error, syscallFilter []string, includeHost bool, sniffMainThreadOnly bool) error {
	sniffer := sniffer_engine.CreateSnifferEngine(syscallFilter, includeHost, sniffMainThreadOnly, "")
	stdout, _, err, cmd := sniffer.StartSnifferEngine()
	if err != nil {
		logger.Print(logger.ERROR, false, "fail to create sniffer agent process\n")
		return err
	}
	go acc.accumulateSnifferData(stdout)
	go waitToProcessErrCode(cmd, errChan)
	return nil
}

func (acc *ContainerAccumulator) StartContainerAccumalator(errChan chan error, resourceName string, syscallFilter []string, includeHost bool, sniffMainThreadOnly bool) error {
	sniffer := sniffer_engine.CreateSnifferEngine(syscallFilter, includeHost, sniffMainThreadOnly, acc.containerID)
	logger.Print(logger.INFO, false, "starting runtime sniffer for container %s in k8s resource %s\n", acc.containerID, resourceName)
	stdout, pid, err, cmd := sniffer.StartSnifferEngine()
	if err != nil {
		logger.Print(logger.ERROR, false, "fail to create sniffer agent process\n")
		errChan <- err
		return err
	}
	acc.watcherPID = pid
	go acc.accumulateSnifferData(stdout)
	go waitToProcessErrCode(cmd, errChan)
	return nil
}

func (acc *ContainerAccumulator) StopWatching(errChan chan error) {
	acc.stopWatching = true
	proc, err := os.FindProcess(acc.watcherPID)
	if err != nil {
		errFromChannel := <-errChan
		logger.Print(logger.ERROR, false, "failed to stop watcher pid %d, the sniffer process for containerID %s failed with error: %v\n", acc.watcherPID, acc.containerID, errFromChannel)
	} else {
		err = proc.Signal(os.Kill)
		if err != nil {
			logger.Print(logger.ERROR, false, "failed to stop watcher pid %d\n", acc.watcherPID)
		}
	}
}

func GetCacheAccumaltor() *CacheAccumulator {
	return cacheAccumuator
}

func IsBeforeContainerStartTime(containerStartTime v1.Time, timestamp v1.Time) bool {
	return timestamp.UTC().Before(timestamp.Time.UTC())
}

func (acc *CacheAccumulator) AccumulatorByContainerID(aggregationData *[]MetadataAccumulator, containerID string, containerStartTime interface{}) {
	for i := range acc.accumultorData {
		logger.Print(logger.DEBUG, false, "%d:%v\n", i, acc.accumultorData[i])
	}
	for i := range acc.accumultorData {
		for j := range acc.accumultorData[i][containerID] {
			// logger.Print(logger.DEBUG, false, "before if: AccumulatorByContainerID acc.accumultorData[i][containerID][j].Timestamp %v\n", acc.accumultorData[i][containerID][j].Timestamp)
			// logger.Print(logger.DEBUG, false, "before if: AccumulatorByContainerID acc.accumultorData[i][containerID][j].Timestamp %v\n", acc.accumultorData[i][containerID][j].Timestamp)
			// acc.accumultorData[i][containerID][j].Timestamp.Sub(time.Time(accumultorData[i][containerID][j].Timestamp.Nanosecond()))
			// t := v1.NewTime(acc.accumultorData[i][containerID][j].Timestamp)
			// if IsBeforeContainerStartTime(containerStartTime.(v1.Time), t) {
			// 	logger.Print(logger.DEBUG, false, "append data acc.accumultorData[%d][%s][%d] %v", i, containerID, j, acc.accumultorData[i][containerID][j])
			// 	logger.Print(logger.DEBUG, false, "AccumulatorByContainerID acc.accumultorData[i][containerID][j].Timestamp %v\n", acc.accumultorData[i][containerID][j].Timestamp)
			// 	*aggregationData = append(*aggregationData, acc.accumultorData[i][containerID][j])
			// }
			*aggregationData = append(*aggregationData, acc.accumultorData[i][containerID][j])
		}
	}
	logger.Print(logger.DEBUG, false, "data %v\n", aggregationData)
}

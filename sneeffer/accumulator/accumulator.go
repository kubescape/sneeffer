package accumulator

import (
	"strings"
	"sync"
	"time"

	"github.com/kubescape/sneeffer/internal/logger"

	"github.com/kubescape/sneeffer/sneeffer/accumulator_data_structure"

	"github.com/kubescape/sneeffer/sneeffer/ebpf_engine"

	"github.com/kubescape/sneeffer/internal/config"
)

type containersAccumalator struct {
	accumultorDataPerContainer map[string]chan accumulator_data_structure.MetadataAccumulator
	registerContainerState     bool
	unregisterContainerState   bool
	registerMutex              sync.Mutex
}

type CacheAccumulator struct {
	accumultorData                  []map[string][]accumulator_data_structure.MetadataAccumulator
	syncReaderWriterAccumulatorData sync.Mutex
	firstMapKeysOfAccumultorData    []string
	cacheAccumulatorSize            int
	mainDataChannel                 chan *accumulator_data_structure.MetadataAccumulator
	containersData                  containersAccumalator
	ebpfEngine                      ebpf_engine.EbpfEngineClient
}

type ContainerAccumulator struct {
	dataChannel chan accumulator_data_structure.MetadataAccumulator
	containerID string
}

var cacheAccumuator *CacheAccumulator

func CreateCacheAccumulator(cacheAccumulatorSize int) *CacheAccumulator {
	cacheAccumuator = &CacheAccumulator{
		cacheAccumulatorSize:         cacheAccumulatorSize,
		accumultorData:               make([]map[string][]accumulator_data_structure.MetadataAccumulator, cacheAccumulatorSize),
		firstMapKeysOfAccumultorData: make([]string, cacheAccumulatorSize),
		mainDataChannel:              make(chan *accumulator_data_structure.MetadataAccumulator),
		containersData: containersAccumalator{
			accumultorDataPerContainer: make(map[string]chan accumulator_data_structure.MetadataAccumulator),
			registerContainerState:     false,
			unregisterContainerState:   false,
		},
	}

	return cacheAccumuator
}

func CreateContainerAccumulator(containerID string, dataChannel chan accumulator_data_structure.MetadataAccumulator) *ContainerAccumulator {
	return &ContainerAccumulator{
		dataChannel: dataChannel,
		containerID: containerID,
	}
}

func (acc *CacheAccumulator) createNewMap(event *accumulator_data_structure.MetadataAccumulator, index int) {
	slice := make([]accumulator_data_structure.MetadataAccumulator, 0)
	m := make(map[string][]accumulator_data_structure.MetadataAccumulator)
	m[event.ContainerID] = slice
	acc.accumultorData[index] = m
	acc.firstMapKeysOfAccumultorData[index] = event.ContainerID
}

func (acc *CacheAccumulator) findIndexByTimestampWhenAccumultorDataIsFull(event *accumulator_data_structure.MetadataAccumulator) int {
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
	acc.createNewMap(event, index)
	return index
}

func (acc *CacheAccumulator) findIndexByTimestamp(event *accumulator_data_structure.MetadataAccumulator) int {
	for i := range acc.accumultorData {
		if len(acc.accumultorData[i]) == 0 {
			acc.createNewMap(event, i)
			return i
		}
		firstKey := acc.firstMapKeysOfAccumultorData[i]
		if event.Timestamp.Sub((acc.accumultorData[i])[firstKey][0].Timestamp) < time.Second {
			return i
		}
	}
	index := acc.findIndexByTimestampWhenAccumultorDataIsFull(event)
	if index != -1 {
		return index
	}
	return -1
}

func (acc *CacheAccumulator) removeAllStreamedContainers(event *accumulator_data_structure.MetadataAccumulator) {
	if acc.containersData.unregisterContainerState || acc.containersData.registerContainerState {
		acc.containersData.registerMutex.Lock()
	}
	if len(acc.containersData.accumultorDataPerContainer) > 0 {
		for contID := range acc.containersData.accumultorDataPerContainer {
			acc.containersData.accumultorDataPerContainer[contID] <- *event
		}
	}
	if acc.containersData.unregisterContainerState || acc.containersData.registerContainerState {
		acc.containersData.registerMutex.Unlock()
	}
}

func (acc *CacheAccumulator) addEventToCacheAccumalator(event *accumulator_data_structure.MetadataAccumulator, index int) {
	acc.syncReaderWriterAccumulatorData.Lock()
	a := acc.accumultorData[index]
	a[event.ContainerID] = append(a[event.ContainerID], *event)
	acc.accumultorData[index][event.ContainerID] = append(acc.accumultorData[index][event.ContainerID], *event)
	acc.syncReaderWriterAccumulatorData.Unlock()
}

func (acc *CacheAccumulator) streamEventToListeningContainer(event *accumulator_data_structure.MetadataAccumulator, index int) {
	if acc.containersData.unregisterContainerState || acc.containersData.registerContainerState {
		acc.containersData.registerMutex.Lock()
	}
	if containerAccumalatorChan, exist := acc.containersData.accumultorDataPerContainer[event.ContainerID]; exist {
		containerAccumalatorChan <- *event
	}
	if acc.containersData.unregisterContainerState || acc.containersData.registerContainerState {
		acc.containersData.registerMutex.Unlock()
	}
}

func (acc *CacheAccumulator) accumulateEbpfEngineData() {
	for {
		event := <-acc.mainDataChannel
		if strings.Contains(event.ContainerID, config.GetMyContainerID()) {
			continue
		}
		if event != nil {
			if event.Cmd == "drop event occured\n" {
				acc.removeAllStreamedContainers(event)
			} else {
				index := acc.findIndexByTimestamp(event)
				if index == -1 {
					continue
				}
				acc.addEventToCacheAccumalator(event, index)
				acc.streamEventToListeningContainer(event, index)
			}
		}
	}
}

func (acc *CacheAccumulator) getEbpfEngineData() {
	acc.ebpfEngine.GetEbpfEngineData(acc.mainDataChannel)
}

func (acc *CacheAccumulator) getEbpfEngineError(errChan chan error) {
	errChan <- acc.ebpfEngine.GetEbpfEngineError()
}

func (acc *CacheAccumulator) StartCacheAccumalator(errChan chan error, syscallFilter []string, includeHost bool, sniffMainThreadOnly bool) error {
	if config.IsFalcoEbpfEngine() {
		falcoEbpfEngine := ebpf_engine.CreateFalcoEbpfEngine(syscallFilter, includeHost, sniffMainThreadOnly, "")
		acc.ebpfEngine = falcoEbpfEngine
	} else {
		ciliumEbpfEngine := ebpf_engine.CreateCiliumEbpfEngine()
		acc.ebpfEngine = ciliumEbpfEngine
	}
	err := acc.ebpfEngine.StartEbpfEngine()
	if err != nil {
		logger.Print(logger.ERROR, false, "fail to create ebpf engine")
		return err
	}

	go acc.accumulateEbpfEngineData()
	go acc.getEbpfEngineData()
	go acc.getEbpfEngineError(errChan)
	return nil
}

func (acc *ContainerAccumulator) registerContainerAccumalator() {
	cacheAccumuator.containersData.registerContainerState = true
	cacheAccumuator.containersData.registerMutex.Lock()
	cacheAccumuator.containersData.accumultorDataPerContainer[acc.containerID] = acc.dataChannel
	cacheAccumuator.containersData.registerMutex.Unlock()
	cacheAccumuator.containersData.registerContainerState = false
}

func (acc *ContainerAccumulator) unregisterContainerAccumalator() {
	cacheAccumuator.containersData.unregisterContainerState = true
	cacheAccumuator.containersData.registerMutex.Lock()
	delete(cacheAccumuator.containersData.accumultorDataPerContainer, acc.containerID)
	cacheAccumuator.containersData.registerMutex.Unlock()
	cacheAccumuator.containersData.unregisterContainerState = false
}

func (acc *ContainerAccumulator) StartContainerAccumalator() {
	acc.registerContainerAccumalator()
}

func (acc *ContainerAccumulator) StopWatching() {
	acc.unregisterContainerAccumalator()
}

func GetCacheAccumaltor() *CacheAccumulator {
	return cacheAccumuator
}

func (acc *CacheAccumulator) AccumulatorByContainerID(aggregationData *[]accumulator_data_structure.MetadataAccumulator, containerID string, containerStartTime interface{}) {
	for i := range acc.accumultorData {
		logger.Print(logger.DEBUG, false, "index %d:%v", i, acc.accumultorData[i])
	}
	for i := range acc.accumultorData {
		for j := range acc.accumultorData[i][containerID] {
			acc.syncReaderWriterAccumulatorData.Lock()
			*aggregationData = append(*aggregationData, acc.accumultorData[i][containerID][j])
			acc.syncReaderWriterAccumulatorData.Unlock()
		}
	}
	logger.Print(logger.DEBUG, false, "%v", aggregationData)
}

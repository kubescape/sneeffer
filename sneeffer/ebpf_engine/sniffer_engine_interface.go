package ebpf_engine

import "github.com/kubescape/sneeffer/sneeffer/accumulator_data_structure"

type EbpfEngineClient interface {
	StartEbpfEngine() error
	GetEbpfEngineData(chan *accumulator_data_structure.MetadataAccumulator)
	GetEbpfEngineError() error
}

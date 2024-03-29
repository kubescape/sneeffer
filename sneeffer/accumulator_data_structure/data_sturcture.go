package accumulator_data_structure

import "time"

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

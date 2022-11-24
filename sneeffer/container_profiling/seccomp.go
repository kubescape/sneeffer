package container_profiling

type syscallsData struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

type SeccompData struct {
	DefaultAction string         `json:"defaultAction" mapstructure:"defaultAction"`
	Syscalls      []syscallsData `json:"syscalls"`
}

func CreateSeccompProfile(syscalls []string) *SeccompData {
	return &SeccompData{
		DefaultAction: "SCMP_ACT_LOG",
		Syscalls: []syscallsData{{
			Names:  syscalls,
			Action: "SCMP_ACT_ALLOW",
		}},
	}
}

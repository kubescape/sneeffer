package network_policy

type NetworkPolicyGen struct {
	K8sAncestorName string `json:"ancestorName,omitempty"`
	NetworkPolicy   string `json:"networkPolicy"`
}

package vuln

import "github.com/kubescape/sneeffer/sneeffer/sbom"

type vulnInterface interface {
	CreateVulnObject(imageID string, sbomObject sbom.SbomObject) *vulnInterface
	GetImageVulnerabilities(errChan chan error) bool
	GetFilterVulnerabilities() error
}

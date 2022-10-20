package sbom

type SbomInterface interface {
	CreateSbomObject(imageID string) (*SbomInterface, error)
	CreateSbomUnfilter(errChan chan error) bool
	SetSbom(sbomData []byte) bool
	FilterSbom(realTimeFileList []string) error
	GetSbomFilePath() string
}

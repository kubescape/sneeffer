package sbom

import (
	"github.com/anchore/syft/syft/source"
	"github.com/sirupsen/logrus"
)

type anchore struct {
	// upload options
	Host string `yaml:"host" json:"host" mapstructure:"host"` // -H , hostname of the engine/enterprise instance to upload to (setting this value enables upload)
	Path string `yaml:"path" json:"path" mapstructure:"path"` // override the engine/enterprise API upload path
	// IMPORTANT: do not show the username in any YAML/JSON output (sensitive information)
	Username string `yaml:"-" json:"-" mapstructure:"username"` // -u , username to authenticate upload
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password               string `yaml:"-" json:"-" mapstructure:"password"`                                                               // -p , password to authenticate upload
	Dockerfile             string `yaml:"dockerfile" json:"dockerfile" mapstructure:"dockerfile"`                                           // -d , dockerfile to attach for upload
	OverwriteExistingImage bool   `yaml:"overwrite-existing-image" json:"overwrite-existing-image" mapstructure:"overwrite-existing-image"` // --overwrite-existing-image , if any of the SBOM components have already been uploaded this flag will ensure they are overwritten with the current upload
	ImportTimeout          uint   `yaml:"import-timeout" json:"import-timeout" mapstructure:"import-timeout"`                               // --import-timeout
	// , customize the number of seconds within which the SBOM import must be completed or canceled
}

type development struct {
	ProfileCPU bool `yaml:"profile-cpu" json:"profile-cpu" mapstructure:"profile-cpu"`
	ProfileMem bool `yaml:"profile-mem" json:"profile-mem" mapstructure:"profile-mem"`
}

type logging struct {
	Structured   bool         `yaml:"structured" json:"structured" mapstructure:"structured"` // show all log entries as JSON formatted strings
	LevelOpt     logrus.Level `yaml:"-" json:"-"`                                             // the native log level object used by the logger
	Level        string       `yaml:"level" json:"level" mapstructure:"level"`                // the log level string hint
	FileLocation string       `yaml:"file" json:"file-location" mapstructure:"file"`          // the file path to write logs to
}

type pkg struct {
	Cataloger               catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SearchUnindexedArchives bool             `yaml:"search-unindexed-archives" json:"search-unindexed-archives" mapstructure:"search-unindexed-archives"`
	SearchIndexedArchives   bool             `yaml:"search-indexed-archives" json:"search-indexed-archives" mapstructure:"search-indexed-archives"`
}

type catalogerOptions struct {
	Enabled  bool         `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Scope    string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	ScopeOpt source.Scope `yaml:"-" json:"-"`
}

type FileMetadata struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	Digests   []string         `yaml:"digests" json:"digests" mapstructure:"digests"`
}

type fileClassification struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

type fileContents struct {
	Cataloger          catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SkipFilesAboveSize int64            `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
	Globs              []string         `yaml:"globs" json:"globs" mapstructure:"globs"`
}

type secrets struct {
	Cataloger           catalogerOptions  `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	AdditionalPatterns  map[string]string `yaml:"additional-patterns" json:"additional-patterns" mapstructure:"additional-patterns"`
	ExcludePatternNames []string          `yaml:"exclude-pattern-names" json:"exclude-pattern-names" mapstructure:"exclude-pattern-names"`
	RevealValues        bool              `yaml:"reveal-values" json:"reveal-values" mapstructure:"reveal-values"`
	SkipFilesAboveSize  int64             `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
}

type RegistryCredentials struct {
	Authority string `yaml:"authority" json:"authority" mapstructure:"authority"`
	// IMPORTANT: do not show the username in any YAML/JSON output (sensitive information)
	Username string `yaml:"username" json:"username" mapstructure:"username"`
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password string `yaml:"password" json:"password" mapstructure:"password"`
	// IMPORTANT: do not show the token in any YAML/JSON output (sensitive information)
	Token string `yaml:"-" json:"-" mapstructure:"token"`
}

type registry struct {
	InsecureSkipTLSVerify bool                  `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool                  `yaml:"insecure-use-http" json:"insecure-use-http" mapstructure:"insecure-use-http"`
	Auth                  []RegistryCredentials `yaml:"auth" json:"auth" mapstructure:"auth"`
}

type attest struct {
	KeyRef                   string `yaml:"key" json:"key" mapstructure:"key"` // same as --key, file path to the private key
	Cert                     string `yaml:"cert" json:"cert" mapstructure:"cert"`
	NoUpload                 bool   `yaml:"no_upload" json:"noUpload" mapstructure:"no_upload"`
	Force                    bool   `yaml:"force" json:"force" mapstructure:"force"`
	Recursive                bool   `yaml:"recursive" json:"recursive" mapstructure:"recursive"`
	Replace                  bool   `yaml:"replace" json:"replace" mapstructure:"replace"`
	Password                 string `yaml:"-" json:"-" mapstructure:"password"` // password for the private key
	FulcioURL                string `yaml:"fulcio_url" json:"fulcioUrl" mapstructure:"fulcio_url"`
	FulcioIdentityToken      string `yaml:"fulcio_identity_token" json:"fulcio_identity_token" mapstructure:"fulcio_identity_token"`
	InsecureSkipFulcioVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify" mapstructure:"insecure_skip_verify"`
	RekorURL                 string `yaml:"rekor_url" json:"rekorUrl" mapstructure:"rekor_url"`
	OIDCIssuer               string `yaml:"oidc_issuer" json:"oidcIssuer" mapstructure:"oidc_issuer"`
	OIDCClientID             string `yaml:"oidc_client_id" json:"oidcClientId" mapstructure:"oidc_client_id"`
	OIDCRedirectURL          string `yaml:"oidc_redirect_url" json:"OIDCRedirectURL" mapstructure:"oidc_redirect_url"`
}

type ExternalSources struct {
	ExternalSourcesEnabled bool `yaml:"external-sources-enabled" json:"external-sources-enabled" mapstructure:"external-sources-enabled"`
}

// Application is the main syft application configuration.
type Application struct {
	// the location where the application config was read from (either from -c or discovered while loading); default .syft.yaml
	ConfigPath string `yaml:"configPath,omitempty" json:"configPath" mapstructure:"config"`
	Verbosity  uint   `yaml:"verbosity,omitempty" json:"verbosity" mapstructure:"verbosity"`
	// -q, indicates to not show any status output to stderr (ETUI or logging UI)
	Quiet              bool               `yaml:"quiet" json:"quiet" mapstructure:"quiet"`
	Outputs            []string           `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the format to use for output
	OutputTemplatePath string             `yaml:"output-template-path" json:"output-template-path" mapstructure:"output-template-path"` // -t template file to use for output
	File               string             `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	CheckForAppUpdate  bool               `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Anchore            anchore            `yaml:"anchore" json:"anchore" mapstructure:"anchore"`                                        // options for interacting with Anchore Engine/Enterprise
	Dev                development        `yaml:"dev" json:"dev" mapstructure:"dev"`
	Log                logging            `yaml:"log" json:"log" mapstructure:"log"` // all logging-related options
	Catalogers         []string           `yaml:"catalogers" json:"catalogers" mapstructure:"catalogers"`
	Package            pkg                `yaml:"package" json:"package" mapstructure:"package"`
	FileMetadata       FileMetadata       `yaml:"file-metadata" json:"file-metadata" mapstructure:"file-metadata"`
	FileClassification fileClassification `yaml:"file-classification" json:"file-classification" mapstructure:"file-classification"`
	FileContents       fileContents       `yaml:"file-contents" json:"file-contents" mapstructure:"file-contents"`
	Secrets            secrets            `yaml:"secrets" json:"secrets" mapstructure:"secrets"`
	Registry           registry           `yaml:"registry" json:"registry" mapstructure:"registry"`
	Exclusions         []string           `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	Attest             attest             `yaml:"attest" json:"attest" mapstructure:"attest"`
	Platform           string             `yaml:"platform" json:"platform" mapstructure:"platform"`
	ExternalSources    ExternalSources    `yaml:"external_sources" json:"external_sources" mapstructure:"external_sources"`
}

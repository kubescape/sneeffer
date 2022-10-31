package vuln

import (
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
	"github.com/sirupsen/logrus"
)

type CliOnlyOptions struct {
	ConfigPath string
	Verbosity  int
}

type search struct {
	ScopeOpt                 source.Scope `yaml:"-" json:"-"`
	Scope                    string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	IncludeUnindexedArchives bool         `yaml:"unindexed-archives" json:"unindexed-archives" mapstructure:"unindexed-archives"`
	IncludeIndexedArchives   bool         `yaml:"indexed-archives" json:"indexed-archives" mapstructure:"indexed-archives"`
}

type database struct {
	Dir                   string        `yaml:"cache-dir" json:"cache-dir" mapstructure:"cache-dir"`
	UpdateURL             string        `yaml:"update-url" json:"update-url" mapstructure:"update-url"`
	CACert                string        `yaml:"ca-cert" json:"ca-cert" mapstructure:"ca-cert"`
	AutoUpdate            bool          `yaml:"auto-update" json:"auto-update" mapstructure:"auto-update"`
	ValidateByHashOnStart bool          `yaml:"validate-by-hash-on-start" json:"validate-by-hash-on-start" mapstructure:"validate-by-hash-on-start"`
	ValidateAge           bool          `yaml:"validate-age" json:"validate-age" mapstructure:"validate-age"`
	MaxAllowedBuiltAge    time.Duration `yaml:"max-allowed-built-age" json:"max-allowed-built-age" mapstructure:"max-allowed-built-age"`
}

type externalSources struct {
	Enable bool  `yaml:"enable" json:"enable" mapstructure:"enable"`
	Maven  maven `yaml:"maven" json:"maven" mapsructure:"maven"`
}

type maven struct {
	SearchUpstreamBySha1 bool   `yaml:"search-upstream" json:"searchUpstreamBySha1" mapstructure:"search-maven-upstream"`
	BaseURL              string `yaml:"base-url" json:"baseUrl" mapstructure:"base-url"`
}

type development struct {
	ProfileCPU bool `yaml:"profile-cpu" json:"profile-cpu" mapstructure:"profile-cpu"`
	ProfileMem bool `yaml:"profile-mem" json:"profile-mem" mapstructure:"profile-mem"`
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

type logging struct {
	Structured   bool         `yaml:"structured" json:"structured" mapstructure:"structured"` // show all log entries as JSON formatted strings
	LevelOpt     logrus.Level `yaml:"-" json:"-"`                                             // the native log level object used by the logger
	Level        string       `yaml:"level" json:"level" mapstructure:"level"`                // the log level string hint
	FileLocation string       `yaml:"file" json:"file" mapstructure:"file"`                   // the file path to write logs to
}

type Attestation struct {
	PublicKey        string `yaml:"public-key" json:"public-key" mapstructure:"public-key"`
	SkipVerification bool   `yaml:"skip-verification" json:"skip-verification" mapstructure:"skip-verification"`
}

type Application struct {
	ConfigPath          string                  `yaml:",omitempty" json:"configPath"`                                                         // the location where the application config was read from (either from -c or discovered while loading)
	Output              string                  `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the Presenter hint string to use for report formatting
	File                string                  `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	Distro              string                  `yaml:"distro" json:"distro" mapstructure:"distro"`                                           // --distro, specify a distro to explicitly use
	GenerateMissingCPEs bool                    `yaml:"add-cpes-if-none" json:"add-cpes-if-none" mapstructure:"add-cpes-if-none"`             // --add-cpes-if-none, automatically generate CPEs if they are not present in import (e.g. from a 3rd party SPDX document)
	OutputTemplateFile  string                  `yaml:"output-template-file" json:"output-template-file" mapstructure:"output-template-file"` // -t, the template file to use for formatting the final report
	Quiet               bool                    `yaml:"quiet" json:"quiet" mapstructure:"quiet"`                                              // -q, indicates to not show any status output to stderr (ETUI or logging UI)
	CheckForAppUpdate   bool                    `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	OnlyFixed           bool                    `yaml:"only-fixed" json:"only-fixed" mapstructure:"only-fixed"`                               // only fail if detected vulns have a fix
	OnlyNotFixed        bool                    `yaml:"only-notfixed" json:"only-notfixed" mapstructure:"only-notfixed"`                      // only fail if detected vulns don't have a fix
	Platform            string                  `yaml:"platform" json:"platform" mapstructure:"platform"`                                     // --platform, override the target platform for a container image
	CliOptions          CliOnlyOptions          `yaml:"-" json:"-"`
	Search              search                  `yaml:"search" json:"search" mapstructure:"search"`
	Ignore              []match.IgnoreRule      `yaml:"ignore" json:"ignore" mapstructure:"ignore"`
	Exclusions          []string                `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	DB                  database                `yaml:"db" json:"db" mapstructure:"db"`
	ExternalSources     externalSources         `yaml:"external-sources" json:"externalSources" mapstructure:"external-sources"`
	Dev                 development             `yaml:"dev" json:"dev" mapstructure:"dev"`
	FailOn              string                  `yaml:"fail-on-severity" json:"fail-on-severity" mapstructure:"fail-on-severity"`
	FailOnSeverity      *vulnerability.Severity `yaml:"-" json:"-"`
	Registry            registry                `yaml:"registry" json:"registry" mapstructure:"registry"`
	Log                 logging                 `yaml:"log" json:"log" mapstructure:"log"`
	Attestation         Attestation             `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
}

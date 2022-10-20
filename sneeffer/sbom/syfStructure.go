package sbom

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Descriptor describes what created the document as well as surrounding metadata
type Descriptor struct {
	Name          string      `json:"name"`
	Version       string      `json:"version"`
	Configuration interface{} `json:"configuration,omitempty"`
}

type Schema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type IDLikes []string

type LinuxRelease struct {
	PrettyName       string  `json:"prettyName,omitempty"`
	Name             string  `json:"name,omitempty"`
	ID               string  `json:"id,omitempty"`
	IDLike           IDLikes `json:"idLike,omitempty"`
	Version          string  `json:"version,omitempty"`
	VersionID        string  `json:"versionID,omitempty"`
	VersionCodename  string  `json:"versionCodename,omitempty"`
	BuildID          string  `json:"buildID,omitempty"`
	ImageID          string  `json:"imageID,omitempty"`
	ImageVersion     string  `json:"imageVersion,omitempty"`
	Variant          string  `json:"variant,omitempty"`
	VariantID        string  `json:"variantID,omitempty"`
	HomeURL          string  `json:"homeURL,omitempty"`
	SupportURL       string  `json:"supportURL,omitempty"`
	BugReportURL     string  `json:"bugReportURL,omitempty"`
	PrivacyPolicyURL string  `json:"privacyPolicyURL,omitempty"`
	CPEName          string  `json:"cpeName,omitempty"`
}

// Source object represents the thing that was cataloged
type Source struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

type Secrets struct {
	Location source.Coordinates  `json:"location"`
	Secrets  []file.SearchResult `json:"secrets"`
}

type File struct {
	ID              string                `json:"id"`
	Location        source.Coordinates    `json:"location"`
	Metadata        *FileMetadataEntry    `json:"metadata,omitempty"`
	Contents        string                `json:"contents,omitempty"`
	Digests         []file.Digest         `json:"digests,omitempty"`
	Classifications []file.Classification `json:"classifications,omitempty"`
}

type FileMetadataEntry struct {
	Mode            int             `json:"mode"`
	Type            source.FileType `json:"type"`
	LinkDestination string          `json:"linkDestination,omitempty"`
	UserID          int             `json:"userID"`
	GroupID         int             `json:"groupID"`
	MIMEType        string          `json:"mimeType"`
}

type Relationship struct {
	Parent   string      `json:"parent"`
	Child    string      `json:"child"`
	Type     string      `json:"type"`
	Metadata interface{} `json:"metadata,omitempty"`
}

// PackageCustomData contains ambiguous values (type-wise) from pkg.Package.
type PackageCustomData struct {
	MetadataType pkg.MetadataType `json:"metadataType,omitempty"`
	Metadata     interface{}      `json:"metadata,omitempty"`
}

// PackageBasicData contains non-ambiguous values (type-wise) from pkg.Package.
type PackageBasicData struct {
	ID        string               `json:"id"`
	Name      string               `json:"name"`
	Version   string               `json:"version"`
	Type      pkg.Type             `json:"type"`
	FoundBy   string               `json:"foundBy"`
	Locations []source.Coordinates `json:"locations"`
	Licenses  []string             `json:"licenses"`
	Language  pkg.Language         `json:"language"`
	CPEs      []string             `json:"cpes"`
	PURL      string               `json:"purl"`
}

// Package represents a pkg.Package object specialized for JSON marshaling and unmarshalling.
type Package struct {
	PackageBasicData
	PackageCustomData
}

// Document represents the syft cataloging findings as a JSON document
type Document struct {
	Artifacts             []Package      `json:"artifacts"` // Artifacts is the list of packages discovered and placed into the catalog
	ArtifactRelationships []Relationship `json:"artifactRelationships"`
	Files                 []File         `json:"files,omitempty"`   // note: must have omitempty
	Secrets               []Secrets      `json:"secrets,omitempty"` // note: must have omitempty
	Source                Source         `json:"source"`            // Source represents the original object that was cataloged
	Distro                LinuxRelease   `json:"distro"`            // Distro represents the Linux distribution that was detected from the source
	Descriptor            Descriptor     `json:"descriptor"`        // Descriptor is a block containing self-describing information about syft
	Schema                Schema         `json:"schema"`            // Schema is a block reserved for defining the version for the shape of this JSON document and where to find the schema document to validate the shape
}

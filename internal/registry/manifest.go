package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// --- Media types ------------------------------------------------------------

// Media types for the manifest shapes we read and write. We support both the
// Docker Schema 2 lineage (still the default from many registries) and the OCI
// image spec, because "verify any image" means not caring which a registry used.
const (
	MediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerConfig       = "application/vnd.docker.container.image.v1+json"
	MediaTypeOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex           = "application/vnd.oci.image.index.v1+json"
	MediaTypeOCIConfig          = "application/vnd.oci.image.config.v1+json"
	// MediaTypeEmptyJSON is the OCI "empty" config blob ("{}"), used as the
	// config of a referrer artifact that carries its data elsewhere.
	MediaTypeEmptyJSON = "application/vnd.oci.empty.v1+json"
)

// manifestMediaTypes is the set the client advertises in its Accept header.
func manifestMediaTypes() string {
	return MediaTypeOCIIndex + ", " + MediaTypeOCIManifest + ", " +
		MediaTypeDockerManifestList + ", " + MediaTypeDockerManifest
}

// --- Descriptors & manifests ------------------------------------------------

// Descriptor points at content in a registry by digest, size, and media type.
// It is the OCI spec's universal "here is a blob/manifest" reference.
type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// Manifest is an image manifest (Docker Schema 2 or OCI image manifest). The
// Subject field (OCI 1.1) turns a manifest into a referrer: it declares that
// this manifest is *about* another manifest (the subject), which is how
// signatures and attestations attach to an image.
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Subject       *Descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Index is an image index / manifest list: a set of manifests, one per platform
// (or, for a referrers response, one per referring artifact).
type Index struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Manifests     []Descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Digest computes the OCI content digest of bytes: "sha256:<hex>". A manifest's
// digest is the digest of its exact bytes, which is why callers must digest the
// bytes they received, never a re-serialization (re-marshaling can change bytes).
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifyDigest checks that content hashes to want. A registry (or a
// man-in-the-middle) that serves content not matching the digest you asked for
// is either buggy or hostile; either way, fail.
func VerifyDigest(content []byte, want string) error {
	if got := Digest(content); got != want {
		return fmt.Errorf("digest mismatch: content is %s but expected %s", got, want)
	}
	return nil
}

// IsIndex reports whether a media type denotes a multi-manifest index/list.
func IsIndex(mediaType string) bool {
	return mediaType == MediaTypeOCIIndex || mediaType == MediaTypeDockerManifestList
}

// ParseManifest decodes manifest bytes into a Manifest.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// ParseIndex decodes index bytes into an Index.
func ParseIndex(data []byte) (*Index, error) {
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	return &idx, nil
}

// RawManifest is a fetched manifest with the exact bytes, its digest, and its
// media type. Keeping the raw bytes matters: the digest and any signature are
// over these bytes, so re-serializing would break verification.
type RawManifest struct {
	Bytes     []byte
	MediaType string
	Digest    string
}

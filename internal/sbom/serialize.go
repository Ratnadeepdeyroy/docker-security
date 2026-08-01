package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Format names a supported SBOM serialization.
type Format string

const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
)

// Formats lists the supported SBOM output formats.
func Formats() []Format { return []Format{FormatCycloneDX, FormatSPDX} }

// DocMeta carries the document-level, time-varying fields that must be injected
// (rather than sampled from the ambient clock) so output stays deterministic.
// In tests these are set to fixed values; in production the command fills them.
type DocMeta struct {
	Timestamp   time.Time
	Serial      string // stable document identifier (uuid or digest-derived)
	ToolName    string
	ToolVersion string
}

func (m DocMeta) toolName() string {
	if m.ToolName == "" {
		return "docker-security"
	}
	return m.ToolName
}

func (m DocMeta) timestamp() string {
	return m.Timestamp.UTC().Format(time.RFC3339)
}

// Marshal serializes an SBOM into the requested format. The SBOM is normalized
// (deduplicated and sorted) first, so identical inputs yield byte-identical
// documents for a fixed DocMeta.
func Marshal(s *SBOM, format Format, meta DocMeta) ([]byte, error) {
	norm := *s
	norm.Components = append([]Component(nil), s.Components...)
	norm.Relationships = append([]Relationship(nil), s.Relationships...)
	norm.normalize()
	switch format {
	case FormatCycloneDX:
		return marshalCycloneDX(&norm, meta)
	case FormatSPDX:
		return marshalSPDX(&norm, meta)
	default:
		return nil, fmt.Errorf("unknown SBOM format %q (want one of: cyclonedx, spdx)", format)
	}
}

// encodeJSON renders v as indented JSON without HTML-escaping, so PURLs keep
// their literal "&", "<", and ">" characters (as SBOM tooling expects) instead
// of "&" etc. The output ends with a trailing newline.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DeterministicUUID derives a stable RFC 4122-shaped UUID (version 5 layout)
// from a seed string, so the same input always yields the same identifier
// without sampling randomness or the clock.
func DeterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

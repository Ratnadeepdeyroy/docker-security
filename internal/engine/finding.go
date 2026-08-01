package engine

import "strings"

// Severity is an ordered risk level. Higher values are more severe, so
// findings sort and gate naturally by numeric comparison.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	case SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverity parses a case-insensitive severity name. Unrecognized input
// (including the empty string) yields SeverityUnknown.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	case "INFO":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// MarshalJSON renders severities as their string names in JSON output.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON parses a severity from its string name, so an engine.Report
// serialized to JSON round-trips back into the model (used by the result store
// and the policy engine). An unrecognized or non-string value becomes
// SeverityUnknown rather than erroring, keeping ingestion resilient.
func (s *Severity) UnmarshalJSON(data []byte) error {
	str := strings.Trim(string(data), `"`)
	*s = ParseSeverity(str)
	return nil
}

// Location points at where in a resource a finding was detected.
type Location struct {
	Path      string `json:"path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

// Finding is a single security issue reported by a module.
type Finding struct {
	RuleID      string            `json:"rule_id"`
	Module      string            `json:"module"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	Location    *Location         `json:"location,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

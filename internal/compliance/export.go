package compliance

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ExportFormat names a supported compliance report serialization.
type ExportFormat string

const (
	ExportJSON  ExportFormat = "json"
	ExportCSV   ExportFormat = "csv"
	ExportOSCAL ExportFormat = "oscal" // NIST OSCAL assessment-results (subset)
	ExportMD    ExportFormat = "md"    // human auditor packet
)

// ExportFormats lists the supported formats.
func ExportFormats() []ExportFormat {
	return []ExportFormat{ExportJSON, ExportCSV, ExportOSCAL, ExportMD}
}

// Render serializes a ComplianceReport in the requested format. Output is
// deterministic for a fixed report (ids derive from content, not randomness).
func Render(rep *ComplianceReport, format ExportFormat) ([]byte, error) {
	switch format {
	case ExportJSON, "":
		b, err := json.MarshalIndent(rep, "", "  ")
		return append(b, '\n'), err
	case ExportCSV:
		return renderCSV(rep)
	case ExportOSCAL:
		return renderOSCAL(rep)
	case ExportMD:
		return renderMarkdown(rep), nil
	default:
		return nil, fmt.Errorf("unknown compliance export format %q (want json|csv|oscal|md)", format)
	}
}

func renderCSV(rep *ComplianceReport) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"framework", "version", "control", "title", "assessment", "disposition", "verdict", "check", "observed", "maps_to"})
	for _, r := range rep.Results {
		_ = w.Write([]string{
			r.Framework, r.Version, r.ID, r.Title, r.Assessment, string(r.Disposition),
			r.Evidence.Verdict, r.Evidence.Check, r.Evidence.Observed, flattenMaps(r.MapsTo),
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func flattenMaps(m map[string][]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+":"+strings.Join(m[k], "/"))
	}
	return strings.Join(parts, "; ")
}

// --- OSCAL assessment-results (subset) -------------------------------------

type oscalDoc struct {
	AR oscalAR `json:"assessment-results"`
}
type oscalAR struct {
	UUID     string        `json:"uuid"`
	Metadata oscalMeta     `json:"metadata"`
	Results  []oscalResult `json:"results"`
}
type oscalMeta struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}
type oscalResult struct {
	UUID     string         `json:"uuid"`
	Title    string         `json:"title"`
	Start    string         `json:"start"`
	Findings []oscalFinding `json:"findings"`
}
type oscalFinding struct {
	UUID   string      `json:"uuid"`
	Title  string      `json:"title"`
	Target oscalTarget `json:"target"`
}
type oscalTarget struct {
	Type     string      `json:"type"`
	TargetID string      `json:"target-id"`
	Status   oscalStatus `json:"status"`
}
type oscalStatus struct {
	State  string `json:"state"` // satisfied | not-satisfied
	Reason string `json:"reason,omitempty"`
}

func renderOSCAL(rep *ComplianceReport) ([]byte, error) {
	doc := oscalDoc{AR: oscalAR{
		UUID: detUUID(rep.Target + "|assessment"),
		Metadata: oscalMeta{
			Title:        "docker-security compliance assessment: " + rep.Target,
			LastModified: rep.GeneratedAt,
			Version:      rep.ToolVersion,
			OSCALVersion: "1.1.2",
		},
	}}
	res := oscalResult{
		UUID:  detUUID(rep.Target + "|result"),
		Title: "Automated control assessment",
		Start: rep.GeneratedAt,
	}
	for _, r := range rep.Results {
		res.Findings = append(res.Findings, oscalFinding{
			UUID:  detUUID(r.Framework + "|" + r.ID),
			Title: fmt.Sprintf("%s %s — %s", r.Framework, r.ID, r.Title),
			Target: oscalTarget{
				Type:     "objective-id",
				TargetID: r.Framework + ":" + r.ID,
				Status:   oscalStatus{State: oscalState(r.Disposition), Reason: r.Evidence.Observed},
			},
		})
	}
	doc.AR.Results = []oscalResult{res}
	b, err := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n'), err
}

func oscalState(d Disposition) string {
	switch d {
	case DispSatisfied, DispWaived, DispNotApplicable:
		return "satisfied"
	default:
		return "not-satisfied"
	}
}

// --- Markdown auditor packet -----------------------------------------------

func renderMarkdown(rep *ComplianceReport) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Compliance report — %s\n\n", rep.Target)
	fmt.Fprintf(&b, "Generated %s · tool docker-security %s · frameworks: %s\n\n",
		rep.GeneratedAt, rep.ToolVersion, strings.Join(rep.Frameworks, ", "))

	b.WriteString("## Coverage\n\n")
	b.WriteString("| Framework | Coverage | Satisfied | Failed | Waived | N/A | Manual | Total |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, s := range Coverage(rep) {
		fmt.Fprintf(&b, "| %s | %.1f%% | %d | %d | %d | %d | %d | %d |\n",
			s.Framework, s.CoveragePct, s.Satisfied, s.Failed, s.Waived, s.NotApplicable, s.Manual, s.Total)
	}

	if gaps := Gaps(rep); len(gaps) > 0 {
		b.WriteString("\n## Gaps (action required)\n\n")
		for _, g := range gaps {
			fmt.Fprintf(&b, "- **[%s] %s %s** — %s\n  - %s\n", g.Disposition, g.Framework, g.ID, g.Title, g.Evidence.Observed)
			if g.Remediation != "" {
				fmt.Fprintf(&b, "  - Remediation: %s\n", g.Remediation)
			}
		}
	}

	b.WriteString("\n## Controls\n\n")
	b.WriteString("| Framework | Control | Disposition | Verdict | Observed |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, r := range rep.Results {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", r.Framework, r.ID, r.Disposition, r.Evidence.Verdict, r.Evidence.Observed)
	}
	return []byte(b.String())
}

// detUUID derives a stable RFC-4122-shaped id from a seed so exports are
// byte-reproducible without sampling randomness.
func detUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

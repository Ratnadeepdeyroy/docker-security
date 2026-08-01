package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// --- AI-age feature: continuous-compliance narrative -----------------------
//
// This is the "evidence that writes itself" layer from the phase handoff. It
// turns a Report (plus an optional prior baseline and live waivers) into a
// structured summary an AI agent can post to leadership/GRC: a score, the
// framework coverage, what moved since last run, and the worst open failures
// with their guided remediation.
//
// It is OFF BY DEFAULT: nothing here runs during a normal scan. A caller must
// explicitly opt in (BuildNarrative), and the module only does so when the
// operator sets the narrative flag/metadata. It is deterministic — the clock is
// injected via NarrativeOptions.Now, never read from the wall.

// NarrativeItem is one highlighted control (a failure or a fix) with the
// machine-consumable context an agent needs to reason about or act on it.
type NarrativeItem struct {
	ControlID   string         `json:"control_id"`
	Title       string         `json:"title"`
	Status      Status         `json:"status"`
	Section     string         `json:"section,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Frameworks  []FrameworkRef `json:"frameworks,omitempty"`
	Fix         *Fix           `json:"fix,omitempty"`
}

// FrameworkLine is one row of framework coverage for dashboards.
type FrameworkLine struct {
	Framework Framework `json:"framework"`
	Controls  int       `json:"controls"`
}

// Narrative is the structured "state of compliance" summary. It marshals to
// JSON for machine consumers and renders to prose via Text() for humans.
type Narrative struct {
	Benchmark   string          `json:"benchmark"`
	Version     string          `json:"version"`
	Profile     string          `json:"profile,omitempty"`
	GeneratedAt string          `json:"generated_at"`
	Score       int             `json:"score"`
	Counts      map[string]int  `json:"counts"`
	Frameworks  []FrameworkLine `json:"frameworks"`
	Drift       *Drift          `json:"drift,omitempty"`
	TopFailures []NarrativeItem `json:"top_failures,omitempty"`
	Expiring    []Waiver        `json:"expiring_waivers,omitempty"`
}

// NarrativeOptions parameterizes narrative generation. Now is mandatory and is
// the injected clock that keeps output deterministic in tests and reproducible
// in production.
type NarrativeOptions struct {
	Now         time.Time // injected timestamp (required for determinism)
	Baseline    *Report   // prior run, for the since-last-run drift section
	Waivers     *Waivers  // to surface soon-to-expire exceptions
	MaxFailures int       // cap on TopFailures (0 ⇒ default of 5)
}

// BuildNarrative assembles the narrative from a report. It performs no I/O and
// reads no ambient state, so identical inputs yield an identical narrative.
func BuildNarrative(rep *Report, opts NarrativeOptions) *Narrative {
	max := opts.MaxFailures
	if max <= 0 {
		max = 5
	}

	counts := map[string]int{}
	for status, n := range rep.Counts() {
		counts[status.String()] = n
	}

	controls := make([]Control, 0, len(rep.Results))
	for _, r := range rep.Results {
		controls = append(controls, r.Control)
	}
	cov := FrameworkCoverage(controls)
	lines := make([]FrameworkLine, 0, len(cov))
	for _, fw := range SortedFrameworks(cov) {
		lines = append(lines, FrameworkLine{Framework: fw, Controls: cov[fw]})
	}

	n := &Narrative{
		Benchmark:   rep.Benchmark,
		Version:     rep.Version,
		Profile:     rep.Profile,
		GeneratedAt: opts.Now.UTC().Format(time.RFC3339),
		Score:       rep.Score(),
		Counts:      counts,
		Frameworks:  lines,
	}

	// Worst open failures first (Level 1 before Level 2, then control id), so
	// the agent leads with the highest-leverage fixes.
	failing := rep.Failing()
	sort.SliceStable(failing, func(i, j int) bool {
		li, lj := failing[i].Control.Level, failing[j].Control.Level
		if li != lj {
			return li < lj // Level1 (smaller) ranks ahead of Level2
		}
		return compareControlID(failing[i].Control.ID, failing[j].Control.ID)
	})
	for i, r := range failing {
		if i >= max {
			break
		}
		n.TopFailures = append(n.TopFailures, NarrativeItem{
			ControlID:   r.Control.ID,
			Title:       r.Control.Title,
			Status:      r.Status,
			Section:     r.Control.Section,
			Remediation: r.Control.Remediation,
			Frameworks:  r.Control.Frameworks,
			Fix:         r.Control.Fix,
		})
	}

	if opts.Baseline != nil {
		n.Drift = Diff(opts.Baseline, rep)
	}
	if opts.Waivers != nil {
		n.Expiring = opts.Waivers.Expiring(30*24*time.Hour, opts.Now)
	}
	return n
}

// Text renders the narrative as a human-readable brief suitable for a status
// post. It is deterministic and side-effect free.
func (n *Narrative) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (v%s", n.Benchmark, n.Version)
	if n.Profile != "" {
		fmt.Fprintf(&b, ", profile %s", n.Profile)
	}
	fmt.Fprintf(&b, ") — compliance score %d%% as of %s\n", n.Score, n.GeneratedAt)
	fmt.Fprintf(&b, "Controls: %d passed, %d failed, %d warnings, %d informational.\n",
		n.Counts[StatusPass.String()], n.Counts[StatusFail.String()],
		n.Counts[StatusWarn.String()], n.Counts[StatusInfo.String()])

	if n.Drift != nil && n.Drift.HasDrift() {
		fmt.Fprintf(&b, "Since the last run: %d regressed, %d fixed (score %d%%→%d%%).\n",
			len(n.Drift.Regressed), len(n.Drift.Fixed), n.Drift.ScoreFrom, n.Drift.ScoreTo)
		for _, e := range n.Drift.Regressed {
			fmt.Fprintf(&b, "  ! REGRESSED %s %s (%s→%s)\n", e.ControlID, e.Title, e.From, e.To)
		}
	}

	if len(n.TopFailures) > 0 {
		fmt.Fprintf(&b, "Top open failures:\n")
		for _, f := range n.TopFailures {
			fmt.Fprintf(&b, "  - [%s] %s %s\n    fix: %s\n", f.Status, f.ControlID, f.Title, f.Remediation)
		}
	}

	if len(n.Frameworks) > 0 {
		parts := make([]string, 0, len(n.Frameworks))
		for _, fl := range n.Frameworks {
			parts = append(parts, fmt.Sprintf("%s=%d", fl.Framework, fl.Controls))
		}
		fmt.Fprintf(&b, "Framework coverage: %s\n", strings.Join(parts, ", "))
	}

	for _, w := range n.Expiring {
		fmt.Fprintf(&b, "Waiver expiring soon: control %s (%s) — %s\n", w.Control, w.Expires, w.Reason)
	}
	return b.String()
}

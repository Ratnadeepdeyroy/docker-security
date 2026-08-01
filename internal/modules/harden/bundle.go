package harden

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	hardenlib "github.com/Ratnadeepdeyroy/docker-security/internal/harden"
)

// --- Module-side hardening bundle (off by default) ---------------------------
//
// When the bundle feature is enabled, each verified workload also gets a
// DS-RAT-BOX-900 finding carrying the full agent-appliable bundle as JSON. Analyze
// always builds it in DryRun mode — the engine's analysis path never mutates
// anything — so an agent reads the plan and applies it through its own change
// path. The observation used for profile generation and the clock used for
// exception expiry are injected via target metadata, keeping Analyze
// deterministic (no ambient time, no surprise file reads unless asked).

// bundleFinding builds the agent-appliable hardening bundle for a workload and
// wraps it in an INFO finding. The heavy content lives in Metadata["bundle"] as
// JSON; the Description is a human summary.
func bundleFinding(w *hardenlib.Workload, rep *hardenlib.Report, t *engine.Target) engine.Finding {
	opts := hardenlib.BundleOptions{
		Observation: loadObservation(t),
		Now:         bundleClock(t),
		DryRun:      true,
	}
	b := hardenlib.BuildBundle(w, rep, opts)

	summary := fmt.Sprintf("Agent-appliable hardening bundle (dry-run): addresses %d control(s) [%s], seccomp in %s mode.",
		len(b.Addressed), strings.Join(b.Addressed, ", "), b.SeccompMode)
	if len(b.Waived) > 0 {
		summary += fmt.Sprintf(" %d control(s) waived by active exception.", len(b.Waived))
	}

	md := map[string]string{"seccomp_mode": b.SeccompMode}
	if data, err := json.Marshal(b); err == nil {
		md["bundle"] = string(data)
	}

	return engine.Finding{
		RuleID:      "DS-RAT-BOX-900",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       "Agent-appliable hardening bundle",
		Description: summary,
		Resource:    w.Name,
		Remediation: "Apply the securityContext patch and generated profiles in Metadata[\"bundle\"]; waivers are expiry-bound and lapse automatically.",
		References:  []string{"NIST SP 800-190 4.5.3"},
		Metadata:    md,
	}
}

// loadObservation reads a recorded/declared Observation from the path in target
// metadata "harden.observation" when present; otherwise it returns the empty
// observation (a valid, bootstrap-only profile is still generated).
func loadObservation(t *engine.Target) hardenlib.Observation {
	if t.Metadata == nil {
		return hardenlib.Observation{}
	}
	path := t.Metadata["harden.observation"]
	if path == "" {
		return hardenlib.Observation{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return hardenlib.Observation{}
	}
	var obs hardenlib.Observation
	if err := json.Unmarshal(data, &obs); err != nil {
		return hardenlib.Observation{}
	}
	return obs
}

// bundleClock returns the injected time for exception-expiry evaluation. Analysis
// never reads the wall clock, so an absent/blank metadata value yields the zero
// time (all exceptions with a future expiry are active, deterministically).
func bundleClock(t *engine.Target) time.Time {
	if t.Metadata == nil {
		return time.Time{}
	}
	if s := t.Metadata["harden.now"]; s != "" {
		if ts, err := time.Parse(time.RFC3339, s); err == nil {
			return ts
		}
	}
	return time.Time{}
}

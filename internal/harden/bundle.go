package harden

import (
	"sort"
	"time"
)

// --- Agent-appliable hardening bundle (AI-age feature, off by default) --------
//
// This closes the profile-from-behaviour loop for an autonomous platform agent:
// given a workload's verification report and an observation of its behaviour, it
// produces a single structured artifact an agent can apply — a securityContext
// patch that fixes the failing controls, plus a generated least-privilege
// seccomp/AppArmor profile — together with a "what this newly blocks" diff so the
// blast radius is visible before anything changes.
//
// Two properties make it safe to hand to automation:
//   - Nothing here mutates a host. The bundle is a plan; DryRun records intent.
//   - Exceptions are expiry-bound. An agent may waive a control, but only with a
//     reason and an expiry; once the clock (injected, never ambient) passes the
//     expiry the waiver lapses and the finding returns. There are no permanent
//     silent waivers — the classic way security debt hides forever.

// Exception is a time-boxed acceptance of a specific control failure.
type Exception struct {
	// ControlID is the rule this waives, e.g. "DS-RAT-BOX-006".
	ControlID string `json:"control_id"`
	// Reason is the human/agent justification (required in spirit; not enforced).
	Reason string `json:"reason,omitempty"`
	// GrantedBy identifies who or what created the exception.
	GrantedBy string `json:"granted_by,omitempty"`
	// Expires is when the waiver lapses. The zero time means "never", which the
	// bundle flags as discouraged rather than honouring silently forever.
	Expires time.Time `json:"expires"`
}

// activeAt reports whether the exception is still in force at now. A zero expiry
// is treated as active (never expires) but is separately flagged as discouraged.
func (e Exception) activeAt(now time.Time) bool {
	return e.Expires.IsZero() || now.Before(e.Expires)
}

// ApplyExceptions returns a copy of the report with Fail/Warn results dropped
// when an *active* exception covers their control. Expired exceptions are
// ignored, so their findings reappear — that is the whole point of the expiry.
// Pure and deterministic given the injected now.
func (r *Report) ApplyExceptions(exceptions []Exception, now time.Time) *Report {
	active := map[string]bool{}
	for _, e := range exceptions {
		if e.activeAt(now) {
			active[e.ControlID] = true
		}
	}
	out := &Report{Workload: r.Workload}
	for _, res := range r.Results {
		if active[res.Control.ID] && (res.Status == StatusFail || res.Status == StatusWarn) {
			continue // waived, still in force
		}
		out.Results = append(out.Results, res)
	}
	return out
}

// BundleOptions parameterises bundle construction.
type BundleOptions struct {
	// Observation drives least-privilege profile generation. An empty observation
	// still yields a valid (bootstrap-only) seccomp profile plus a RuntimeDefault
	// recommendation.
	Observation Observation
	// Exceptions are the operator/agent's time-boxed waivers.
	Exceptions []Exception
	// Now is the injected clock used to evaluate expiry. Callers in a frontend
	// pass time.Now(); tests pass a fixed instant.
	Now time.Time
	// PriorSeccomp, when set, is the profile currently applied; the bundle then
	// includes the allow-set diff so the agent sees what tightening newly blocks.
	PriorSeccomp *SeccompProfile
	// DryRun marks the bundle as a plan to preview rather than apply.
	DryRun bool
}

// HardeningBundle is the structured, agent-appliable output.
type HardeningBundle struct {
	Workload string `json:"workload"`
	DryRun   bool   `json:"dry_run"`

	// SecurityContext is the patch to merge into the workload's securityContext /
	// runtime config to fix the addressed controls. Values are concrete and
	// minimal; an agent applies them verbatim.
	SecurityContext map[string]any `json:"security_context,omitempty"`

	// Seccomp is the generated least-privilege profile (nil only on error).
	Seccomp *SeccompProfile `json:"seccomp,omitempty"`
	// SeccompMode is "enforce" or "audit" — audit when the observation is not yet
	// believed complete, so tightening does not break an incompletely-traced app.
	SeccompMode string `json:"seccomp_mode"`
	// AppArmor is the rendered least-privilege AppArmor profile text.
	AppArmor string `json:"apparmor,omitempty"`
	// SeccompDiff, when PriorSeccomp was given, is what switching newly blocks.
	SeccompDiff *SeccompDiff `json:"seccomp_diff,omitempty"`

	// Addressed lists the control IDs this bundle fixes (sorted).
	Addressed []string `json:"addressed,omitempty"`
	// Waived lists control IDs suppressed by an active exception (sorted).
	Waived []AppliedException `json:"waived,omitempty"`
	// Warnings surfaces bundle-construction caveats (e.g. a never-expiring waiver).
	Warnings []string `json:"warnings,omitempty"`
}

// AppliedException is an active exception recorded in the bundle.
type AppliedException struct {
	ControlID string `json:"control_id"`
	Reason    string `json:"reason,omitempty"`
	Expires   string `json:"expires,omitempty"` // RFC3339, empty = never
}

// BuildBundle assembles a hardening bundle from a workload, its verification
// report, and options. It fixes every still-failing control it knows how to fix,
// generates confinement profiles from the observation, and records active
// (unexpired) exceptions.
func BuildBundle(w *Workload, rep *Report, opts BundleOptions) *HardeningBundle {
	b := &HardeningBundle{
		Workload:        w.Name,
		DryRun:          opts.DryRun,
		SecurityContext: map[string]any{},
	}

	// Which controls remain failing after honouring active exceptions?
	effective := rep.ApplyExceptions(opts.Exceptions, opts.Now)
	failing := map[string]bool{}
	for _, res := range effective.Results {
		if res.Status == StatusFail || res.Status == StatusWarn {
			failing[res.Control.ID] = true
		}
	}

	// Record active exceptions (and warn about never-expiring ones).
	for _, e := range opts.Exceptions {
		if !e.activeAt(opts.Now) {
			continue
		}
		ae := AppliedException{ControlID: e.ControlID, Reason: e.Reason}
		if e.Expires.IsZero() {
			b.Warnings = append(b.Warnings, "exception for "+e.ControlID+" never expires; set an expiry so the waiver is revisited")
		} else {
			ae.Expires = e.Expires.UTC().Format(time.RFC3339)
		}
		b.Waived = append(b.Waived, ae)
	}
	sort.Slice(b.Waived, func(i, j int) bool { return b.Waived[i].ControlID < b.Waived[j].ControlID })

	// Translate failing controls into concrete securityContext fixes.
	b.Addressed = securityContextPatch(w, failing, b.SecurityContext)

	// Generate confinement profiles from observed behaviour. Audit mode until the
	// trace is believed complete, so an under-observed app is not broken.
	seccompOpts := SeccompOptions{Name: profileName(w), AuditMode: !opts.Observation.Complete}
	b.Seccomp = GenerateSeccomp(opts.Observation, seccompOpts)
	if opts.Observation.Complete {
		b.SeccompMode = "enforce"
	} else {
		b.SeccompMode = "audit"
	}
	b.AppArmor = GenerateAppArmor(opts.Observation, profileName(w)).Render()

	if opts.PriorSeccomp != nil {
		d := DiffSeccomp(opts.PriorSeccomp, b.Seccomp)
		b.SeccompDiff = &d
	}
	return b
}

// securityContextPatch fills patch with the concrete fixes for the failing
// controls it recognises and returns the sorted list of controls it addressed.
// Some fixes cover several controls: de-privileging a workload also drops its
// capabilities and disables privilege escalation, so those controls are marked
// addressed too when they were failing.
func securityContextPatch(w *Workload, failing map[string]bool, patch map[string]any) []string {
	addressed := map[string]bool{}
	mark := func(id string) {
		if failing[id] {
			addressed[id] = true
		}
	}
	ensureCapsDropAll := func() {
		caps, _ := patch["capabilities"].(map[string]any)
		if caps == nil {
			caps = map[string]any{}
		}
		caps["drop"] = []string{"ALL"}
		patch["capabilities"] = caps
	}
	noEscalation := func() { patch["allowPrivilegeEscalation"] = false }

	if failing["DS-RAT-BOX-001"] {
		// De-privileging is only safe alongside minimal caps and no escalation, so
		// the fix bundles all three; the related controls are addressed with it.
		patch["privileged"] = false
		ensureCapsDropAll()
		noEscalation()
		for _, id := range []string{"DS-RAT-BOX-001", "DS-RAT-BOX-003", "DS-RAT-BOX-004", "DS-RAT-BOX-005", "DS-RAT-BOX-015"} {
			mark(id)
		}
	}
	if failing["DS-RAT-BOX-002"] {
		patch["runAsNonRoot"] = true
		if w.RunAsUser == nil || *w.RunAsUser == 0 {
			patch["runAsUser"] = 65532 // "nonroot" (distroless) — a safe default
		}
		mark("DS-RAT-BOX-002")
	}
	if failing["DS-RAT-BOX-003"] || failing["DS-RAT-BOX-004"] {
		ensureCapsDropAll()
		mark("DS-RAT-BOX-003")
		mark("DS-RAT-BOX-004")
	}
	if failing["DS-RAT-BOX-005"] || failing["DS-RAT-BOX-015"] {
		noEscalation()
		mark("DS-RAT-BOX-005")
		mark("DS-RAT-BOX-015")
	}
	if failing["DS-RAT-BOX-006"] {
		patch["readOnlyRootFilesystem"] = true
		mark("DS-RAT-BOX-006")
	}
	if failing["DS-RAT-BOX-007"] {
		// Point at the generated profile; RuntimeDefault is the floor if the agent
		// prefers not to ship a custom profile.
		patch["seccompProfile"] = map[string]any{
			"type":             "Localhost",
			"localhostProfile": profileName(w) + ".json",
		}
		mark("DS-RAT-BOX-007")
	}
	if failing["DS-RAT-BOX-008"] {
		patch["appArmorProfile"] = map[string]any{
			"type":             "Localhost",
			"localhostProfile": profileName(w),
		}
		mark("DS-RAT-BOX-008")
	}
	if failing["DS-RAT-BOX-012"] && w.MemoryLimitBytes == 0 {
		patch["memoryLimit"] = "512Mi" // conservative default; operator tunes
		mark("DS-RAT-BOX-012")
	}

	out := make([]string, 0, len(addressed))
	for id := range addressed {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// profileName derives a stable profile name from the workload name.
func profileName(w *Workload) string {
	n := w.Name
	if n == "" {
		n = "workload"
	}
	return sanitizeProfileName("dsecrat-" + n)
}

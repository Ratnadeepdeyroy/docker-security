package harden

import (
	"testing"
	"time"
)

// privilegedWorkload is a deliberately awful workload used to exercise the
// bundle: privileged, root, writable rootfs, no-new-privileges off, unconfined.
func privilegedWorkload() *Workload {
	return &Workload{
		Name:            "bad",
		Privileged:      true,
		RunAsUser:       int64Ptr(0),
		ReadOnlyRootFS:  false,
		NoNewPrivileges: false,
		Seccomp:         SeccompUnconfined,
		Source:          "kubernetes",
	}
}

func TestBundleAddressesFailingControls(t *testing.T) {
	w := privilegedWorkload()
	rep := Verify(w)
	b := BuildBundle(w, rep, BundleOptions{Now: time.Unix(0, 0), DryRun: true})

	if !b.DryRun {
		t.Errorf("Analyze/CLI bundles must be dry-run plans")
	}
	sc := b.SecurityContext
	if sc["privileged"] != false {
		t.Errorf("bundle should set privileged=false, got %v", sc["privileged"])
	}
	if sc["runAsNonRoot"] != true {
		t.Errorf("bundle should set runAsNonRoot=true")
	}
	if sc["readOnlyRootFilesystem"] != true {
		t.Errorf("bundle should set readOnlyRootFilesystem=true")
	}
	if sc["allowPrivilegeEscalation"] != false {
		t.Errorf("bundle should set allowPrivilegeEscalation=false")
	}
	caps, ok := sc["capabilities"].(map[string]any)
	if !ok || caps["drop"] == nil {
		t.Errorf("bundle should drop ALL capabilities, got %v", sc["capabilities"])
	}
	if !contains(b.Addressed, "DS-RAT-BOX-001") || !contains(b.Addressed, "DS-RAT-BOX-007") {
		t.Errorf("addressed controls incomplete: %v", b.Addressed)
	}
}

func TestBundleProfileMode(t *testing.T) {
	w := privilegedWorkload()
	rep := Verify(w)

	// Incomplete observation ⇒ audit mode (do not break an under-traced app).
	audit := BuildBundle(w, rep, BundleOptions{Observation: Observation{Syscalls: []string{"read"}}, Now: time.Unix(0, 0)})
	if audit.SeccompMode != "audit" || audit.Seccomp.DefaultAction != ActLog {
		t.Errorf("incomplete observation should yield audit-mode seccomp, got %q/%q", audit.SeccompMode, audit.Seccomp.DefaultAction)
	}
	// Complete observation ⇒ enforce mode.
	enforce := BuildBundle(w, rep, BundleOptions{Observation: Observation{Syscalls: []string{"read"}, Complete: true}, Now: time.Unix(0, 0)})
	if enforce.SeccompMode != "enforce" || enforce.Seccomp.DefaultAction != ActErrno {
		t.Errorf("complete observation should yield enforce-mode seccomp, got %q/%q", enforce.SeccompMode, enforce.Seccomp.DefaultAction)
	}
	if enforce.AppArmor == "" {
		t.Errorf("bundle should include an AppArmor profile")
	}
}

// TestExpiryBoundExceptionPath is the heart of the AI-age feature: an agent may
// waive a control, but only with an expiry. Before expiry the finding is
// suppressed and the bundle stops trying to fix it; after expiry the waiver
// lapses and the finding returns. Time is injected, never ambient.
func TestExpiryBoundExceptionPath(t *testing.T) {
	w := &Workload{Name: "svc", ReadOnlyRootFS: false, NoNewPrivileges: true, CapDrop: []string{"ALL"}, Seccomp: SeccompRuntimeDefault, RunAsUser: int64Ptr(1000)}
	rep := Verify(w)

	// DS-RAT-BOX-006 (writable rootfs) warns on this workload.
	if statusByID(rep)["DS-RAT-BOX-006"] != StatusWarn {
		t.Fatalf("precondition: DS-RAT-BOX-006 should warn, got %v", statusByID(rep)["DS-RAT-BOX-006"])
	}

	expiry := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	exc := []Exception{{ControlID: "DS-RAT-BOX-006", Reason: "migrating to tmpfs next sprint", GrantedBy: "agent", Expires: expiry}}

	// Before expiry: the waiver is active — finding suppressed, not addressed.
	before := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	effBefore := rep.ApplyExceptions(exc, before)
	if statusByID(effBefore)["DS-RAT-BOX-006"] == StatusWarn {
		t.Errorf("active exception should suppress DS-RAT-BOX-006")
	}
	bBefore := BuildBundle(w, rep, BundleOptions{Now: before, Exceptions: exc})
	if contains(bBefore.Addressed, "DS-RAT-BOX-006") {
		t.Errorf("waived control should not be in Addressed")
	}
	if len(bBefore.Waived) != 1 || bBefore.Waived[0].ControlID != "DS-RAT-BOX-006" {
		t.Errorf("expected DS-RAT-BOX-006 recorded as waived, got %+v", bBefore.Waived)
	}
	if bBefore.Waived[0].Expires == "" {
		t.Errorf("waiver must record its expiry")
	}

	// After expiry: the waiver has lapsed — finding returns.
	after := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	effAfter := rep.ApplyExceptions(exc, after)
	if statusByID(effAfter)["DS-RAT-BOX-006"] != StatusWarn {
		t.Errorf("expired exception must let DS-RAT-BOX-006 reappear")
	}
	bAfter := BuildBundle(w, rep, BundleOptions{Now: after, Exceptions: exc})
	if len(bAfter.Waived) != 0 {
		t.Errorf("expired exception should not be recorded as active, got %+v", bAfter.Waived)
	}
}

func TestNeverExpiringExceptionWarns(t *testing.T) {
	w := &Workload{Name: "svc", ReadOnlyRootFS: false, NoNewPrivileges: true, CapDrop: []string{"ALL"}, Seccomp: SeccompRuntimeDefault, RunAsUser: int64Ptr(1000)}
	rep := Verify(w)
	exc := []Exception{{ControlID: "DS-RAT-BOX-006", Reason: "forever", Expires: time.Time{}}}
	b := BuildBundle(w, rep, BundleOptions{Now: time.Unix(0, 0), Exceptions: exc})
	if len(b.Warnings) == 0 {
		t.Errorf("a never-expiring exception should produce a warning")
	}
}

func TestBundleSeccompDiff(t *testing.T) {
	w := privilegedWorkload()
	rep := Verify(w)
	prior := &SeccompProfile{DefaultAction: ActErrno, Syscalls: []SeccompRule{{Names: []string{"read", "write", "ptrace", "mount"}, Action: ActAllow}}}
	b := BuildBundle(w, rep, BundleOptions{Observation: Observation{Syscalls: []string{"read", "write"}, Complete: true}, Now: time.Unix(0, 0), PriorSeccomp: prior})
	if b.SeccompDiff == nil {
		t.Fatal("expected a seccomp diff when PriorSeccomp is set")
	}
	if !contains(b.SeccompDiff.NewlyBlocked, "ptrace") || !contains(b.SeccompDiff.NewlyBlocked, "mount") {
		t.Errorf("expected ptrace & mount newly blocked, got %v", b.SeccompDiff.NewlyBlocked)
	}
}

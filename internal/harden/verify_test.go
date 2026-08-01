package harden

import (
	"encoding/json"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// verifyFixture parses a spec and verifies its (single) workload.
func verifyFixture(t *testing.T, spec string) *Report {
	t.Helper()
	ws, err := Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ws) == 0 {
		t.Fatal("no workloads parsed")
	}
	return Verify(&ws[0])
}

// statusByID indexes a report by control id (last write wins; fine for the
// single-result controls we assert on here).
func statusByID(r *Report) map[string]Status {
	m := map[string]Status{}
	for _, res := range r.Results {
		m[res.Control.ID] = res.Status
	}
	return m
}

func TestVerifyInsecurePodCatchesEscapes(t *testing.T) {
	rep := verifyFixture(t, insecureKubePod)
	got := statusByID(rep)

	wantFail := map[string]string{
		"DS-RAT-BOX-001": "privileged",
		"DS-RAT-BOX-004": "SYS_ADMIN/NET_ADMIN added",
		"DS-RAT-BOX-007": "seccomp unconfined",
		"DS-RAT-BOX-009": "hostPID",
		"DS-RAT-BOX-010": "docker.sock mounted",
	}
	for id, why := range wantFail {
		if got[id] != StatusFail {
			t.Errorf("control %s (%s): got %v, want FAIL", id, why, got[id])
		}
	}
	// runAsUser 0 with privileged ⇒ root check fails.
	if got["DS-RAT-BOX-002"] != StatusFail {
		t.Errorf("DS-RAT-BOX-002 (root) should FAIL, got %v", got["DS-RAT-BOX-002"])
	}
}

func TestVerifyHardenedOCIPasses(t *testing.T) {
	rep := verifyFixture(t, hardenedOCI)
	for _, res := range rep.Results {
		if res.Status == StatusFail {
			t.Errorf("hardened OCI unexpectedly FAILs %s: %s", res.Control.ID, res.Evidence)
		}
	}
	// Spot-check the controls that should positively pass.
	got := statusByID(rep)
	for _, id := range []string{"DS-RAT-BOX-001", "DS-RAT-BOX-003", "DS-RAT-BOX-005", "DS-RAT-BOX-006", "DS-RAT-BOX-009", "DS-RAT-BOX-014"} {
		if got[id] != StatusPass {
			t.Errorf("control %s should PASS on hardened OCI, got %v", id, got[id])
		}
	}
}

func TestDockerSockCaughtRegardlessOfSide(t *testing.T) {
	// Even when only the destination names the socket, it must be caught.
	w := &Workload{Name: "x", Mounts: []Mount{{Source: "/some/host/path", Destination: "/var/run/docker.sock"}}}
	rep := Verify(w)
	if statusByID(rep)["DS-RAT-BOX-010"] != StatusFail {
		t.Errorf("docker.sock by destination not caught")
	}
}

func TestSensitiveMountSeverityGrading(t *testing.T) {
	cases := []struct {
		src  string
		sev  engine.Severity
		want bool
	}{
		{"/", engine.SeverityCritical, true},
		{"/var/lib/docker/volumes", engine.SeverityCritical, true},
		{"/etc/kubernetes", engine.SeverityHigh, true},
		{"/home/user/data", engine.SeverityMedium, true},
		{"/srv/app", 0, false},
	}
	for _, c := range cases {
		sev, _, ok := sensitiveMountSeverity(c.src)
		if ok != c.want || (ok && sev != c.sev) {
			t.Errorf("sensitiveMountSeverity(%q) = %v,%v; want sev=%v ok=%v", c.src, sev, ok, c.sev, c.want)
		}
	}
}

func TestFindingsSkipPassAndNA(t *testing.T) {
	rep := verifyFixture(t, hardenedOCI)
	fs := rep.Findings("harden")
	for _, f := range fs {
		if f.Module != "harden" {
			t.Errorf("finding has wrong module %q", f.Module)
		}
		if f.RuleID == "" || f.Severity == engine.SeverityUnknown {
			t.Errorf("finding missing rule id or severity: %+v", f)
		}
	}
	// A hardened workload still emits warnings/info (e.g. no AppArmor asserted),
	// but never a Fail.
	for _, f := range fs {
		if f.Severity == engine.SeverityCritical || f.Severity == engine.SeverityHigh {
			t.Errorf("hardened OCI should not emit a high/critical finding: %+v", f)
		}
	}
}

func TestVerifyDeterministic(t *testing.T) {
	ws, _ := Parse([]byte(insecureKubePod))
	first, _ := json.Marshal(Verify(&ws[0]))
	for i := 0; i < 5; i++ {
		again, _ := json.Marshal(Verify(&ws[0]))
		if string(first) != string(again) {
			t.Fatalf("non-deterministic verification on run %d", i)
		}
	}
}

func TestSetuidNeutralizationGap(t *testing.T) {
	// The named market gap: a pod that drops ALL caps but leaves no-new-privileges
	// off is still exposed to setuid escalation.
	w := &Workload{
		Name:            "x",
		CapDrop:         []string{"ALL"},
		NoNewPrivileges: false,
	}
	if statusByID(Verify(w))["DS-RAT-BOX-015"] != StatusWarn {
		t.Errorf("setuid neutralization gap not flagged when no-new-privileges is off")
	}
	// With no-new-privileges on and caps dropped, it is neutralized.
	w.NoNewPrivileges = true
	if statusByID(Verify(w))["DS-RAT-BOX-015"] != StatusPass {
		t.Errorf("setuid should be neutralized with nnp on and ALL dropped")
	}
}

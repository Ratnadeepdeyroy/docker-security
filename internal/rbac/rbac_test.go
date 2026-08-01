package rbac

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// loadFixture parses the committed labeled cluster used across these tests.
func loadFixture(t *testing.T) *Cluster {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "cluster.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	c, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	return c
}

// ruleIDs collects the set of RuleIDs present in a risk slice.
func ruleIDs(rs []Risk) map[string]int {
	m := map[string]int{}
	for _, r := range rs {
		m[r.RuleID]++
	}
	return m
}

func TestParseCounts(t *testing.T) {
	c := loadFixture(t)
	if c.empty() {
		t.Fatal("fixture parsed empty")
	}
	// 6 roles (cluster-admin, secret-reader, binder, pod-manager, impersonator, csr-signer)
	if len(c.Roles) != 6 {
		t.Errorf("roles = %d, want 6", len(c.Roles))
	}
	if len(c.Pods) != 2 {
		t.Errorf("pods = %d, want 2", len(c.Pods))
	}
	if len(c.DockerHosts) != 1 {
		t.Errorf("docker hosts = %d, want 1", len(c.DockerHosts))
	}
	// The privileged pod's securityContext and hostPath must survive parsing.
	var legacy *Pod
	for _, p := range c.Pods {
		if p.Name == "legacy" {
			legacy = p
		}
	}
	if legacy == nil || !legacy.Privileged || len(legacy.HostPathMounts) != 1 {
		t.Errorf("legacy pod not parsed with privileged+hostPath: %+v", legacy)
	}
}

func TestChecksFireExpectedRules(t *testing.T) {
	c := loadFixture(t)
	rep := Analyze(c, Options{})
	got := ruleIDs(rep.Risks)

	// Every parity-checklist primitive present in the fixture must be flagged.
	for _, want := range []string{
		"DS-RAT-RBAC-001", // wildcard
		"DS-RAT-RBAC-002", // cluster-admin
		"DS-RAT-RBAC-004", // bind
		"DS-RAT-RBAC-005", // impersonate
		"DS-RAT-RBAC-006", // secret read
		"DS-RAT-RBAC-007", // pods/exec
		"DS-RAT-RBAC-010", // CSR sign
		"DS-RAT-RBAC-011", // dangling
		"DS-RAT-RBAC-012", // default SA / automount
		"DS-RAT-RBAC-013", // workload creation
		"DS-RAT-RBAC-014", // escalation path
		"DS-RAT-RBAC-015", // docker group
		"DS-RAT-RBAC-016", // docker socket
		"DS-RAT-RBAC-017", // not rootless
		"DS-RAT-RBAC-019", // broad subject
	} {
		if got[want] == 0 {
			t.Errorf("expected at least one %s finding; got none", want)
		}
	}
}

func TestClusterAdminIsCritical(t *testing.T) {
	rep := Analyze(loadFixture(t), Options{})
	found := false
	for _, r := range rep.Risks {
		if r.RuleID == "DS-RAT-RBAC-002" {
			found = true
			if r.Severity != engine.SeverityCritical {
				t.Errorf("cluster-admin finding severity = %s, want CRITICAL", r.Severity)
			}
			if r.Subject != "User/alice" {
				t.Errorf("cluster-admin subject = %q, want User/alice", r.Subject)
			}
		}
	}
	if !found {
		t.Fatal("no DS-RAT-RBAC-002 finding")
	}
}

func TestEscalationPathFromPod(t *testing.T) {
	rep := Analyze(loadFixture(t), Options{})
	// The crafted path: Pod app/web runs as app/reader, which can read Secrets in
	// namespace app, assume SA app/bot, and bot holds 'bind' → cluster-admin.
	var webPath *Risk
	for i := range rep.Risks {
		r := rep.Risks[i]
		if r.RuleID == "DS-RAT-RBAC-014" && r.Subject == "ServiceAccount/app/reader" {
			webPath = &rep.Risks[i]
		}
	}
	if webPath == nil {
		t.Fatalf("expected an escalation path starting from app/reader; risks: %v", ruleIDs(rep.Risks))
	}
	if webPath.Severity != engine.SeverityCritical {
		t.Errorf("escalation severity = %s, want CRITICAL", webPath.Severity)
	}
	if webPath.Resource != "cluster-admin" {
		t.Errorf("escalation target = %q, want cluster-admin", webPath.Resource)
	}
	if len(webPath.Path) < 3 {
		t.Errorf("expected a multi-hop path (pod -> assume SA -> cluster-admin); got %v", webPath.Path)
	}
}

func TestWhoCanReverseQuery(t *testing.T) {
	rep := Analyze(loadFixture(t), Options{})
	// Who can read secrets in namespace app? app/reader (scoped Role) and
	// User/alice (cluster-admin wildcard covers everything).
	subs := rep.WhoCan("get", "", "secrets", "app")
	keys := map[string]bool{}
	for _, s := range subs {
		keys[s.key()] = true
	}
	if !keys["ServiceAccount/app/reader"] {
		t.Errorf("who-can get secrets in app should include app/reader; got %v", keys)
	}
	if !keys["User/alice"] {
		t.Errorf("who-can get secrets should include User/alice via cluster-admin wildcard; got %v", keys)
	}
}

func TestDeterministicOrdering(t *testing.T) {
	// Same input, two runs, byte-identical text report. This is the property the
	// golden test depends on and the contract requires.
	c := loadFixture(t)
	a := Analyze(c, Options{}).Text()
	b := Analyze(loadFixture(t), Options{}).Text()
	if a != b {
		t.Errorf("analysis is not deterministic:\n--- run A ---\n%s\n--- run B ---\n%s", a, b)
	}
}

func TestLeastPrivilegeGeneration(t *testing.T) {
	observed := []Permission{
		{Verb: "get", APIGroup: "", Resource: "pods"},
		{Verb: "list", APIGroup: "", Resource: "pods"},
		{Verb: "get", APIGroup: "apps", Resource: "deployments"},
		{Verb: "get", APIGroup: "", Resource: "pods"}, // duplicate, must collapse
	}
	role := GenerateLeastPrivilege("ServiceAccount/app/reader", observed)
	if len(role.Rules) != 2 {
		t.Fatalf("expected 2 rules (one per apiGroup), got %d: %+v", len(role.Rules), role.Rules)
	}
	// Core group: pods with get+list, deduped and sorted.
	var core *PolicyRule
	for i := range role.Rules {
		if len(role.Rules[i].APIGroups) == 1 && role.Rules[i].APIGroups[0] == "" {
			core = &role.Rules[i]
		}
	}
	if core == nil {
		t.Fatal("no core-group rule generated")
	}
	if len(core.Resources) != 1 || core.Resources[0] != "pods" {
		t.Errorf("core resources = %v, want [pods]", core.Resources)
	}
	if len(core.Verbs) != 2 || core.Verbs[0] != "get" || core.Verbs[1] != "list" {
		t.Errorf("core verbs = %v, want [get list] (sorted, deduped)", core.Verbs)
	}
}

// --- NHI (AI-age feature) is OFF BY DEFAULT --------------------------------

func TestNHIOffByDefault(t *testing.T) {
	rep := Analyze(loadFixture(t), Options{}) // EnableNHI not set
	for _, r := range rep.Risks {
		if r.RuleID == "DS-RAT-RBAC-018" {
			t.Fatalf("NHI finding emitted with NHI disabled: %+v", r)
		}
	}
}

func TestNHIDetectsDormantBroadIdentity(t *testing.T) {
	// infra/agent last used at unix 1_000_000 and holds impersonate (reaches
	// cluster-admin). With "now" far in the future it is dormant AND broad.
	now := time.Unix(1_000_000, 0).Add(200 * 24 * time.Hour)
	rep := Analyze(loadFixture(t), Options{EnableNHI: true, Now: now})
	var dormant bool
	for _, r := range rep.Risks {
		if r.RuleID == "DS-RAT-RBAC-018" && r.Subject == "ServiceAccount/infra/agent" {
			dormant = true
			if r.Meta["dormant"] != "true" {
				t.Errorf("agent should be flagged dormant; meta=%v", r.Meta)
			}
			if r.Meta["reachesTarget"] != "cluster-admin" {
				t.Errorf("agent should reach cluster-admin; meta=%v", r.Meta)
			}
		}
	}
	if !dormant {
		t.Fatalf("expected a dormant NHI finding for infra/agent; got %v", ruleIDs(rep.Risks))
	}
}

func TestNHIDeterministicWithInjectedClock(t *testing.T) {
	now := time.Unix(1_000_000, 0).Add(200 * 24 * time.Hour)
	a := Analyze(loadFixture(t), Options{EnableNHI: true, Now: now}).Text()
	b := Analyze(loadFixture(t), Options{EnableNHI: true, Now: now}).Text()
	if a != b {
		t.Error("NHI analysis is not deterministic under a fixed injected clock")
	}
}

func TestDanglingBindingLow(t *testing.T) {
	rep := Analyze(loadFixture(t), Options{})
	for _, r := range rep.Risks {
		if r.RuleID == "DS-RAT-RBAC-011" {
			if r.Severity != engine.SeverityLow {
				t.Errorf("dangling severity = %s, want LOW", r.Severity)
			}
			return
		}
	}
	t.Fatal("no dangling-binding finding")
}

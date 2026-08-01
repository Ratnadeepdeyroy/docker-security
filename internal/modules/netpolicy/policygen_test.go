package netpolicy

import (
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/netmon"
)

func baselineLog(t *testing.T) *netmon.FlowLog {
	t.Helper()
	c := loadFixture(t, "capture_baseline.json")
	logs := netmon.BuildFlowLogs(c)
	if len(logs) != 1 {
		t.Fatalf("baseline should have 1 workload, got %d", len(logs))
	}
	return logs[0]
}

// TestGeneratePolicyFromBaseline proves the generator turns an observed baseline
// into a least-privilege policy: the named external dest becomes an FQDN
// allowlist entry, IP dests become ipBlock egress rules, and DNS is permitted.
func TestGeneratePolicyFromBaseline(t *testing.T) {
	gp := GeneratePolicy(baselineLog(t), GenOptions{})

	if gp.Namespace != "shop" {
		t.Errorf("namespace = %q, want shop", gp.Namespace)
	}
	// podSelector must be identity/label-based (follows the workload).
	if gp.Policy.PodSelector["app"] != "checkout" {
		t.Errorf("podSelector = %v, want app=checkout", gp.Policy.PodSelector)
	}
	// api.stripe.com is a named external dest -> FQDN allowlist.
	if len(gp.FQDNAllowlist) != 1 || gp.FQDNAllowlist[0].FQDN != "api.stripe.com" {
		t.Errorf("FQDN allowlist = %+v, want [api.stripe.com]", gp.FQDNAllowlist)
	}
	// Egress must include DNS + the two IP dests (db, and the raw-IP one-off).
	var haveDNS, haveDB, haveTor bool
	for _, p := range gp.Policy.Egress {
		if p.NamespaceLabels["kubernetes.io/metadata.name"] == "kube-system" {
			haveDNS = true
		}
		if p.CIDR == "10.9.0.20/32" {
			haveDB = true
		}
		if p.CIDR == "185.220.101.5/32" {
			haveTor = true
		}
	}
	if !haveDNS || !haveDB || !haveTor {
		t.Errorf("egress rules incomplete: dns=%v db=%v tor=%v (%+v)", haveDNS, haveDB, haveTor, gp.Policy.Egress)
	}
	// Without intent modelling nothing is excluded.
	if len(gp.Excluded) != 0 {
		t.Errorf("no exclusions expected without intent, got %+v", gp.Excluded)
	}
}

// TestGenerateWithIntentExcludesAnomalous shows the AI-age intent feature
// tightening the generated policy: the raw-IP/odd-port one-off is classed
// anomalous and kept OFF the policy (recorded under Excluded with a rationale).
func TestGenerateWithIntentExcludesAnomalous(t *testing.T) {
	gp := GeneratePolicy(baselineLog(t), GenOptions{UseIntent: true})

	if len(gp.Excluded) != 1 || gp.Excluded[0].FQDN != "185.220.101.5" {
		t.Fatalf("expected 185.220.101.5 excluded as anomalous, got %+v", gp.Excluded)
	}
	if len(gp.Excluded[0].Rationale) == 0 {
		t.Error("exclusion must carry a rationale an agent can read")
	}
	// The anomalous IP must NOT be in the generated egress rules.
	for _, p := range gp.Policy.Egress {
		if p.CIDR == "185.220.101.5/32" {
			t.Error("anomalous IP leaked into the least-privilege policy")
		}
	}
	// The intended stripe dest must still be allowed and marked intended.
	if len(gp.FQDNAllowlist) != 1 || gp.FQDNAllowlist[0].Class != string(netmon.ClassIntended) {
		t.Errorf("stripe should be allowlisted as intended, got %+v", gp.FQDNAllowlist)
	}
}

// TestDryRunAdmitsBaseline is the DoD requirement: a policy generated from a
// baseline, replayed against that baseline, denies nothing (except IMDS, which
// this workload does not touch). The generated policy fits the observed traffic.
func TestDryRunAdmitsBaseline(t *testing.T) {
	c := loadFixture(t, "capture_baseline.json")
	gp := GeneratePolicy(baselineLog(t), GenOptions{})
	res := DryRun(c, AllowlistFromPolicy(gp))
	if res.DeniedDests != 0 {
		t.Errorf("generated policy denied %d baseline dest(s), want 0: %+v", res.DeniedDests, res.Denied)
	}
	if res.AllowedDests == 0 {
		t.Error("expected the baseline destinations to be allowed")
	}
}

// TestDryRunIntentPolicyDeniesAnomalous shows the tighter, intent-gated policy
// would deny exactly the anomalous destination on replay — the audit an operator
// runs before enforcing.
func TestDryRunIntentPolicyDeniesAnomalous(t *testing.T) {
	c := loadFixture(t, "capture_baseline.json")
	gp := GeneratePolicy(baselineLog(t), GenOptions{UseIntent: true})
	res := DryRun(c, AllowlistFromPolicy(gp))
	if res.DeniedDests != 1 {
		t.Fatalf("intent policy should deny exactly the anomalous dest, denied %d: %+v", res.DeniedDests, res.Denied)
	}
	if res.Denied[0].Dest != "185.220.101.5" {
		t.Errorf("denied dest = %q, want 185.220.101.5", res.Denied[0].Dest)
	}
}

// TestPolicyDiff proves the auto-drafted-change feature: a current policy missing
// the stripe allow yields an "added" entry an agent can apply.
func TestPolicyDiff(t *testing.T) {
	gp := GeneratePolicy(baselineLog(t), GenOptions{})
	generated := AllowlistFromPolicy(gp)

	current := Allowlist{FQDNs: nil, CIDRs: []string{"10.9.0.20/32", "185.220.101.5/32"}, AllowDNS: true}
	d := DiffAllowlists(current, generated)
	if d.Empty() {
		t.Fatal("expected a non-empty diff (stripe allow is missing from current)")
	}
	if len(d.AddedFQDNs) != 1 || d.AddedFQDNs[0] != "api.stripe.com" {
		t.Errorf("added fqdns = %v, want [api.stripe.com]", d.AddedFQDNs)
	}

	// A current policy equal to the generated one yields an empty diff.
	if !DiffAllowlists(generated, generated).Empty() {
		t.Error("identical allowlists should diff empty")
	}
}

// TestRenderGolden pins the rendered YAML for the generated NetworkPolicy, the
// default-deny, and the FQDN allowlist (with intent rationale).
func TestRenderGolden(t *testing.T) {
	gp := GeneratePolicy(baselineLog(t), GenOptions{UseIntent: true})
	bundle := RenderNetworkPolicy(gp.DefaultDeny) + "---\n" +
		RenderNetworkPolicy(gp.Policy) + "---\n" +
		RenderFQDNAllowlist(gp)
	assertGoldenBytes(t, filepath.Join("testdata", "policy_baseline.golden.yaml"), []byte(bundle))
}

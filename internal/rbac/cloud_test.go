package rbac

import (
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// analyzeJSON is a small helper: parse a cluster from JSON and run the full
// check suite, returning the risks.
func analyzeJSON(t *testing.T, jsonDoc string) []Risk {
	t.Helper()
	c, err := LoadBytes([]byte(jsonDoc))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	return Analyze(c, Options{}).Risks
}

func risksByRule(rs []Risk, rule string) []Risk {
	var out []Risk
	for _, r := range rs {
		if r.RuleID == rule {
			out = append(out, r)
		}
	}
	return out
}

func TestCloudIRSAAnnotationDetected(t *testing.T) {
	doc := `{"kind":"ServiceAccount","metadata":{"name":"app","namespace":"prod",
	  "annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::123:role/app"}},
	  "cloud":{"privilege":"admin"}}`
	rs := analyzeJSON(t, doc)
	over := risksByRule(rs, "DS-RAT-RBAC-030")
	if len(over) != 1 {
		t.Fatalf("expected one over-privileged cloud-role risk, got %d: %+v", len(over), rs)
	}
	if over[0].Severity != engine.SeverityCritical {
		t.Errorf("admin-privilege binding should be critical, got %s", over[0].Severity)
	}
	if over[0].Meta["provider"] != "aws" {
		t.Errorf("provider inferred from IRSA annotation = %q, want aws", over[0].Meta["provider"])
	}
	if !strings.Contains(over[0].Meta["cloud_role"], "arn:aws:iam") {
		t.Errorf("cloud_role not captured: %q", over[0].Meta["cloud_role"])
	}
}

func TestCloudGKEWorkloadIdentityDetected(t *testing.T) {
	doc := `{"kind":"ServiceAccount","metadata":{"name":"job","namespace":"batch",
	  "annotations":{"iam.gke.io/gcp-service-account":"job@proj.iam.gserviceaccount.com"}},
	  "cloud":{"privilege":"write"}}`
	rs := analyzeJSON(t, doc)
	over := risksByRule(rs, "DS-RAT-RBAC-030")
	if len(over) != 1 || over[0].Meta["provider"] != "gcp" {
		t.Fatalf("expected one GCP over-privilege risk, got %+v", rs)
	}
	if over[0].Severity != engine.SeverityHigh {
		t.Errorf("write-privilege binding should be high, got %s", over[0].Severity)
	}
}

func TestCloudConfusedDeputyTrust(t *testing.T) {
	doc := `{"kind":"ServiceAccount","metadata":{"name":"svc","namespace":"prod",
	  "annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::123:role/svc"}},
	  "cloud":{"privilege":"read","trustAnyServiceAccount":true}}`
	rs := analyzeJSON(t, doc)
	if len(risksByRule(rs, "DS-RAT-RBAC-031")) != 1 {
		t.Fatalf("expected a confused-deputy trust risk, got %+v", rs)
	}
	// read privilege is not over-privileged, so DS-RAT-RBAC-030 must not fire.
	if len(risksByRule(rs, "DS-RAT-RBAC-030")) != 0 {
		t.Errorf("read-only role should not be flagged over-privileged")
	}
}

func TestCloudDefaultSABinding(t *testing.T) {
	doc := `{"kind":"ServiceAccount","metadata":{"name":"default","namespace":"prod",
	  "annotations":{"azure.workload.identity/client-id":"00000000-0000-0000-0000-000000000000"}},
	  "cloud":{"privilege":"read"}}`
	rs := analyzeJSON(t, doc)
	def := risksByRule(rs, "DS-RAT-RBAC-032")
	if len(def) != 1 || def[0].Meta["provider"] != "azure" {
		t.Fatalf("expected a default-SA cloud-binding risk (azure), got %+v", rs)
	}
}

func TestNoCloudBindingIsQuiet(t *testing.T) {
	doc := `{"kind":"ServiceAccount","metadata":{"name":"plain","namespace":"prod"}}`
	rs := analyzeJSON(t, doc)
	for _, r := range rs {
		if strings.HasPrefix(r.RuleID, "DS-RAT-RBAC-03") {
			t.Errorf("SA with no cloud binding produced a cloud risk: %+v", r)
		}
	}
}

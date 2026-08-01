package admission

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

var fixedNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// updateGolden regenerates golden files: `go test ./internal/admission -update`.
var updateGolden = flag.Bool("update", false, "update golden files")

func loadReviewer(t *testing.T, opts ...Option) *Reviewer {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "admission.policy.json"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	eng, err := policy.CompileBytes(data)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	base := []Option{WithClock(func() time.Time { return fixedNow })}
	return NewReviewer(eng, append(base, opts...)...)
}

func loadReview(t *testing.T, name string) *AdmissionReview {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var ar AdmissionReview
	if err := json.Unmarshal(data, &ar); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return &ar
}

func TestReviewDeniesPrivilegedPod(t *testing.T) {
	rv := loadReviewer(t)
	out := rv.Review(loadReview(t, "review-privileged.json"))
	resp := out.Response

	if resp.UID != "req-privileged-001" {
		t.Fatalf("UID = %q, not echoed", resp.UID)
	}
	if resp.Allowed {
		t.Fatal("privileged pod must be denied")
	}
	if resp.Status == nil || resp.Status.Code != 403 {
		t.Fatalf("expected 403 status, got %+v", resp.Status)
	}
	for _, want := range []string{"no-privileged", "no-hostpath", "no-host-namespaces", "run-as-nonroot"} {
		if !bytes.Contains([]byte(resp.Status.Message), []byte(want)) {
			t.Errorf("deny message missing %q:\n%s", want, resp.Status.Message)
		}
	}
	if resp.AuditAnnotations["docker-security.policy/decision"] != "deny" {
		t.Fatalf("audit decision = %q", resp.AuditAnnotations["docker-security.policy/decision"])
	}
}

func TestReviewAllowsCompliantPod(t *testing.T) {
	rv := loadReviewer(t)
	resp := rv.Review(loadReview(t, "review-compliant.json")).Response
	if !resp.Allowed {
		t.Fatalf("compliant pod must be allowed; status: %+v", resp.Status)
	}
	if len(resp.Warnings) != 0 {
		t.Fatalf("compliant pod should have no warnings, got %v", resp.Warnings)
	}
}

func TestReviewDeniesRootDeployment(t *testing.T) {
	rv := loadReviewer(t)
	resp := rv.Review(loadReview(t, "review-deployment-root.json")).Response
	if resp.Allowed {
		t.Fatal("root deployment must be denied (template extraction)")
	}
	// It is unpinned too, so a digest-pinned warning should ride along.
	if len(resp.Warnings) == 0 {
		t.Fatal("expected a digest-pinned warning")
	}
}

func TestReviewFailsClosedOnMalformedObject(t *testing.T) {
	rv := loadReviewer(t)
	ar := &AdmissionReview{Request: &AdmissionRequest{UID: "x", Object: json.RawMessage(`{bad`)}}
	resp := rv.Review(ar).Response
	if resp.Allowed {
		t.Fatal("malformed object must fail closed (deny)")
	}
}

func TestReviewFailOpenAdmitsOnError(t *testing.T) {
	rv := loadReviewer(t, WithFailOpen(true))
	ar := &AdmissionReview{Request: &AdmissionRequest{UID: "x", Object: json.RawMessage(`{bad`)}}
	resp := rv.Review(ar).Response
	if !resp.Allowed {
		t.Fatal("fail-open must admit on parse error")
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("fail-open admit should carry a warning")
	}
}

// signedResolver marks every image signed — used to prove a signature-requiring
// policy passes only when the image context says so.
type signedResolver struct{}

func (signedResolver) Resolve(string) (policy.AttestationState, []engine.Finding, []string) {
	return policy.StaticAttestation{IsSigned: true}, nil, nil
}

func TestReviewSignatureFailsClosedByDefaultResolver(t *testing.T) {
	// A policy requiring a signature must deny under the default resolver (which
	// vouches for nothing) and allow when a resolver reports the image signed.
	p := `{"version":"1","name":"sig","rules":[{"id":"require-signature","match":"!signed","effect":"deny","severity":"high","message":"unsigned"}]}`
	eng, err := policy.CompileBytes([]byte(p))
	if err != nil {
		t.Fatal(err)
	}
	review := loadReview(t, "review-compliant.json")

	closed := NewReviewer(eng, WithClock(func() time.Time { return fixedNow }))
	if closed.Review(review).Response.Allowed {
		t.Fatal("default resolver must fail closed on a signature requirement")
	}

	open := NewReviewer(eng, WithClock(func() time.Time { return fixedNow }), WithResolver(signedResolver{}))
	if !open.Review(review).Response.Allowed {
		t.Fatal("a signed-image resolver should satisfy the signature requirement")
	}
}

func TestReviewExplainOffByDefault(t *testing.T) {
	// Default: no explanation annotation.
	rv := loadReviewer(t)
	resp := rv.Review(loadReview(t, "review-privileged.json")).Response
	if _, has := resp.AuditAnnotations["docker-security.policy/explanation"]; has {
		t.Fatal("explanation must be off by default")
	}

	// Opt in: a parseable, agent-consumable explanation is attached.
	rvx := loadReviewer(t, WithExplain(true))
	resp = rvx.Review(loadReview(t, "review-privileged.json")).Response
	raw, has := resp.AuditAnnotations["docker-security.policy/explanation"]
	if !has {
		t.Fatal("expected explanation when WithExplain(true)")
	}
	var ex policy.Explanation
	if err := json.Unmarshal([]byte(raw), &ex); err != nil {
		t.Fatalf("explanation not valid JSON: %v", err)
	}
	if ex.Decision != policy.DecisionDeny || len(ex.Denials) == 0 {
		t.Fatalf("explanation = %+v", ex)
	}
}

func TestGoldenPrivilegedResponse(t *testing.T) {
	rv := loadReviewer(t, WithExplain(true))
	resp := rv.Review(loadReview(t, "review-privileged.json"))
	got, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	golden := filepath.Join("testdata", "review-privileged.response.golden.json")
	if *updateGolden {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("response mismatch with golden:\n--- got ---\n%s", got)
	}
}

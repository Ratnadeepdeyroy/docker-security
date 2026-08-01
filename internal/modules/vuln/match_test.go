package vuln

import (
	"context"
	"errors"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

// TestScannerRun_ContextCanceledPropagatesError is a regression test for the
// silent-truncation bug: scanner.run used to break its component loop on
// ctx.Err() and return the partial findings with no error at all, making a
// canceled scan indistinguishable from a genuinely complete one. It must now
// return the ctx error (so Analyze can refuse to present the partial result as
// a successful scan) and must not conflate this with the unrelated
// maxComponents truncation signal (st.truncated).
func TestScannerRun_ContextCanceledPropagatesError(t *testing.T) {
	db, err := vulndb.LoadJSON([]byte(`{"schema":1,"advisories":[]}`))
	if err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}
	doc := &sbom.SBOM{
		Components: []sbom.Component{
			{Type: sbom.TypeLibrary, Name: "leftpad", Version: "1.0.0", PURL: "pkg:npm/leftpad@1.0.0"},
			{Type: sbom.TypeLibrary, Name: "other", Version: "1.0.0", PURL: "pkg:npm/other@1.0.0"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sc := newScanner(db, Options{})
	findings, st, err := sc.run(ctx, doc)
	if err == nil {
		t.Fatal("scanner.run with a canceled context returned a nil error; want a non-nil context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("scanner.run error = %v, want it to wrap context.Canceled", err)
	}
	if findings != nil {
		t.Errorf("scanner.run returned %d findings on immediate cancellation, want none", len(findings))
	}
	if st.truncated {
		t.Error("ctx cancellation must not set st.truncated — that flag is reserved for the maxComponents guard, a distinct, non-error condition")
	}
	if st.components != 0 {
		t.Errorf("st.components = %d, want 0 (canceled before the first component was counted)", st.components)
	}
}

// TestScannerRun_CompletesWithoutErrorWhenNotCanceled is a sanity control for
// the above: an uncanceled context must still return a nil error, so the fix
// doesn't turn every scan into an error.
func TestScannerRun_CompletesWithoutErrorWhenNotCanceled(t *testing.T) {
	db, err := vulndb.LoadJSON([]byte(`{"schema":1,"advisories":[]}`))
	if err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}
	doc := &sbom.SBOM{
		Components: []sbom.Component{
			{Type: sbom.TypeLibrary, Name: "leftpad", Version: "1.0.0", PURL: "pkg:npm/leftpad@1.0.0"},
		},
	}

	sc := newScanner(db, Options{})
	_, st, err := sc.run(context.Background(), doc)
	if err != nil {
		t.Fatalf("scanner.run with a live context returned an error: %v", err)
	}
	if st.components != 1 {
		t.Errorf("st.components = %d, want 1", st.components)
	}
}

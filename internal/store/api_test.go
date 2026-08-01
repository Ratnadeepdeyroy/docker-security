package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// fakeModule is a minimal engine.Module so the API test exercises the real
// scan-and-persist path without importing any capability package.
type fakeModule struct{}

func (fakeModule) Name() string                    { return "fake" }
func (fakeModule) Description() string             { return "test module" }
func (fakeModule) Domains() []string               { return []string{"0"} }
func (fakeModule) Supports(engine.TargetType) bool { return true }
func (fakeModule) Analyze(context.Context, *engine.Target) ([]engine.Finding, error) {
	return []engine.Finding{{RuleID: "DS-RAT-FAKE-1", Module: "fake", Severity: engine.SeverityHigh, Title: "fake finding"}}, nil
}

func testAPI(t *testing.T) (*API, *Store) {
	t.Helper()
	s := seed(t)
	reg := engine.NewRegistry()
	reg.Register(fakeModule{})
	return NewAPI(s, engine.New(reg)), s
}

func serve(t *testing.T, a *API, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	a.Register(mux)
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestAPI_Inventory(t *testing.T) {
	a, _ := testAPI(t)
	w := serve(t, a, "GET", "/v1/inventory", "")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var inv []ImageSummary
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(inv) != 2 || inv[0].Image != "api" {
		t.Errorf("unexpected inventory: %+v", inv)
	}
}

func TestAPI_BlastRadiusEndpoint(t *testing.T) {
	a, _ := testAPI(t)
	w := serve(t, a, "GET", "/v1/inventory/component?name=openssl&version=3.0.1", "")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var resp struct {
		Count   int              `json:"count"`
		Matches []ComponentMatch `json:"matches"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 2 {
		t.Errorf("want 2 matches, got %d", resp.Count)
	}
}

func TestAPI_FindingsFilter(t *testing.T) {
	a, _ := testAPI(t)
	w := serve(t, a, "GET", "/v1/findings?min_severity=high", "")
	var hits []FindingHit
	json.Unmarshal(w.Body.Bytes(), &hits)
	if len(hits) != 2 {
		t.Errorf("want 2 hits >= HIGH, got %d", len(hits))
	}
}

func TestAPI_CreateScanPersists(t *testing.T) {
	a, s := testAPI(t)
	before := s.Len()
	body := `{"type":"dockerfile","location":"Dockerfile","content":"FROM x","image":"newimg","sbom":false,"labels":{"owner":"team-z"}}`
	w := serve(t, a, "POST", "/v1/scans", body)
	if w.Code != 200 {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ScanID    string `json:"scan_id"`
		Persisted bool   `json:"persisted"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Persisted || resp.ScanID == "" {
		t.Fatalf("scan not persisted: %+v", resp)
	}
	if s.Len() != before+1 {
		t.Errorf("store did not grow: before=%d after=%d", before, s.Len())
	}
	// And it is now retrievable + attributed.
	got, ok := s.Get(resp.ScanID)
	if !ok || got.Image != "newimg" || got.Labels["owner"] != "team-z" {
		t.Errorf("stored scan wrong: %+v", got)
	}
}

func TestAPI_CreateScanNoPersist(t *testing.T) {
	a, s := testAPI(t)
	before := s.Len()
	w := serve(t, a, "POST", "/v1/scans", `{"type":"dockerfile","content":"FROM x","image":"tmp","persist":false,"sbom":false}`)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if s.Len() != before {
		t.Errorf("persist=false still wrote to store")
	}
}

func TestAPI_ReadOnlyWithoutEngine(t *testing.T) {
	a := NewAPI(NewMemory(), nil)
	w := serve(t, a, "POST", "/v1/scans", `{"content":"FROM x","image":"x"}`)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("want 501 without engine, got %d", w.Code)
	}
}

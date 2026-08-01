package connector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func sampleReport() *engine.Report {
	return &engine.Report{
		Tool:       "docker-security",
		TargetType: engine.TargetDockerfile,
		Target:     "Dockerfile",
		Findings: []engine.Finding{
			{RuleID: "DS-RAT-DF-001", Module: "dockerfile", Severity: engine.SeverityHigh, Title: "Base image pinned to :latest",
				Location: &engine.Location{Path: "Dockerfile", StartLine: 1}},
		},
	}
}

func TestWebhookSendsJSONReport(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NewWebhook(srv.URL).Send(context.Background(), sampleReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}
	var parsed map[string]any
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if parsed["tool"] != "docker-security" {
		t.Errorf("report tool = %v, want docker-security", parsed["tool"])
	}
}

func TestWebhookErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := NewWebhook(srv.URL).Send(context.Background(), sampleReport()); err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

func TestSlackSendsSummaryText(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NewSlack(srv.URL).Send(context.Background(), sampleReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	text := payload["text"]
	if !strings.Contains(text, "docker-security") || !strings.Contains(text, "DS-RAT-DF-001") {
		t.Errorf("slack text missing expected content: %q", text)
	}
}

func TestSARIFFileWritesValidDoc(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := NewSARIFFile(path).Send(context.Background(), sampleReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `"version": "2.1.0"`) || !strings.Contains(s, "DS-RAT-DF-001") {
		t.Errorf("sarif output missing expected content:\n%s", s)
	}
}

func TestDispatchCollectsErrors(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()

	errs := Dispatch(context.Background(), sampleReport(), NewWebhook(ok.URL), NewWebhook(bad.URL))
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 error, got %d: %v", len(errs), errs)
	}
}

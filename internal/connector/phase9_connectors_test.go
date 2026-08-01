package connector

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// critReport is a fixture with one critical finding, for the Phase 9 connectors.
func critReport() *engine.Report {
	return &engine.Report{
		Tool: "docker-security", TargetType: engine.TargetImage, Target: "acme/api:1.2.3",
		Findings: []engine.Finding{
			{RuleID: "DS-RAT-VULN-042", Module: "vuln", Severity: engine.SeverityCritical,
				Title: "openssl CVE-2022-3602", Resource: "pkg:deb/openssl@3.0.1",
				Remediation: "Upgrade openssl to 3.0.7"},
			{RuleID: "DS-RAT-DF-001", Module: "dockerfile", Severity: engine.SeverityLow, Title: "unpinned base"},
		},
	}
}

func TestJira_CreatesIssue(t *testing.T) {
	var gotPath, gotAuth string
	var payload struct {
		Fields struct {
			Project   struct{ Key string }  `json:"project"`
			IssueType struct{ Name string } `json:"issuetype"`
			Summary   string                `json:"summary"`
		} `json:"fields"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"key":"SEC-1"}`))
	}))
	defer srv.Close()

	j := NewJira(srv.URL, "SEC", "bot@acme.io", "token123")
	if err := j.Send(context.Background(), critReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotPath != "/rest/api/2/issue" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("expected basic auth, got %q", gotAuth)
	}
	if payload.Fields.Project.Key != "SEC" || payload.Fields.IssueType.Name != "Task" {
		t.Errorf("unexpected fields: %+v", payload.Fields)
	}
	if !strings.Contains(payload.Fields.Summary, "acme/api:1.2.3") {
		t.Errorf("summary missing target: %q", payload.Fields.Summary)
	}
}

func TestJira_RespectsMinSeverity(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(201)
	}))
	defer srv.Close()

	j := NewJira(srv.URL, "SEC", "e", "t")
	j.MinSeverity = engine.SeverityCritical
	// A report whose top finding is LOW must not open an issue.
	low := &engine.Report{Target: "x", Findings: []engine.Finding{{RuleID: "DS-RAT-DF-1", Severity: engine.SeverityLow}}}
	if err := j.Send(context.Background(), low); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if called {
		t.Error("issue was created below the severity threshold")
	}
}

func TestSIEM_SendsNDJSONEvents(t *testing.T) {
	var body []byte
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		ct = r.Header.Get("Content-Type")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewSIEM(srv.URL)
	s.APIKey = "Bearer xyz"
	if err := s.Send(context.Background(), critReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if ct != "application/x-ndjson" {
		t.Errorf("content-type = %q", ct)
	}
	// One event per finding, each a standalone JSON object on its own line.
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 NDJSON events, got %d:\n%s", len(lines), body)
	}
	var ev event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("event not valid JSON: %v", err)
	}
	if ev.RuleID != "DS-RAT-VULN-042" || ev.Category != "vulnerability" {
		t.Errorf("unexpected first event: %+v", ev)
	}
}

func TestGitHubCodeScanning_UploadsGzippedBase64SARIF(t *testing.T) {
	var payload struct {
		CommitSHA string `json:"commit_sha"`
		Ref       string `json:"ref"`
		SARIF     string `json:"sarif"`
	}
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"id":"abc","url":"..."}`))
	}))
	defer srv.Close()

	g := NewGitHubCodeScanning("acme", "api", "ghtoken", "deadbeef", "refs/heads/main")
	g.APIBase = srv.URL
	if err := g.Send(context.Background(), critReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotPath != "/repos/acme/api/code-scanning/sarifs" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "token ghtoken" {
		t.Errorf("auth = %q", gotAuth)
	}
	if payload.CommitSHA != "deadbeef" || payload.Ref != "refs/heads/main" {
		t.Errorf("commit/ref wrong: %+v", payload)
	}
	// Decode the SARIF exactly as GitHub would: base64 → gunzip → JSON.
	raw, err := base64.StdEncoding.DecodeString(payload.SARIF)
	if err != nil {
		t.Fatalf("sarif not base64: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("sarif not gzipped: %v", err)
	}
	sarif, _ := io.ReadAll(zr)
	if !strings.Contains(string(sarif), "DS-RAT-VULN-042") || !strings.Contains(string(sarif), `"version": "2.1.0"`) {
		t.Errorf("decoded sarif missing expected content:\n%s", sarif)
	}
}

func TestMCPPush_SendsJSONRPCNotification(t *testing.T) {
	var msg struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			Target string `json:"target"`
			Report struct {
				Tool string `json:"tool"`
			} `json:"report"`
		} `json:"params"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&msg)
		w.WriteHeader(http.StatusNoContent) // MCP servers answer 204 to notifications
	}))
	defer srv.Close()

	if err := NewMCPPush(srv.URL).Send(context.Background(), critReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if msg.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q", msg.JSONRPC)
	}
	if msg.ID != nil {
		t.Errorf("a notification must carry no id, got %v", msg.ID)
	}
	if msg.Method != "notifications/scan_completed" {
		t.Errorf("method = %q", msg.Method)
	}
	if msg.Params.Target != "acme/api:1.2.3" || msg.Params.Report.Tool != "docker-security" {
		t.Errorf("params wrong: %+v", msg.Params)
	}
}

func TestPhase9Connectors_ErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	conns := []Connector{
		NewJira(srv.URL, "P", "e", "t"),
		NewSIEM(srv.URL),
		func() Connector { g := NewGitHubCodeScanning("o", "r", "t", "c", "ref"); g.APIBase = srv.URL; return g }(),
		NewMCPPush(srv.URL),
	}
	for _, c := range conns {
		if err := c.Send(context.Background(), critReport()); err == nil {
			t.Errorf("%s: expected error on 500, got nil", c.Name())
		}
	}
}

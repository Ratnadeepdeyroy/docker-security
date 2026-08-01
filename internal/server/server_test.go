package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/modules"
)

// postJSON drives an endpoint and returns status + decoded body.
func postJSON(t *testing.T, srv *Server, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestSBOMEndpoint(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	apk := filepath.Join(dir, "lib", "apk", "db")
	os.MkdirAll(apk, 0o755)
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("ID=alpine\nVERSION_ID=3.19\n"), 0o644)
	os.WriteFile(filepath.Join(apk, "installed"), []byte("P:musl\nV:1.2.4-r2\nA:x86_64\n\n"), 0o644)

	code, body := postJSON(t, srv, "/v1/sbom", `{"type":"filesystem","location":"`+dir+`"}`)
	if code != http.StatusOK {
		t.Fatalf("/v1/sbom = %d, want 200 (%v)", code, body)
	}
	comps, _ := body["components"].([]any)
	if len(comps) == 0 {
		t.Errorf("/v1/sbom returned no components")
	}
}

func TestDockerImagesEndpoint(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/v1/docker/images", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/docker/images = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	// The endpoint always answers with an "available" flag (false when the host
	// has no docker), so the dashboard can hide the picker gracefully.
	if _, ok := body["available"]; !ok {
		t.Errorf("response missing 'available' flag: %v", body)
	}
}

func TestDockerTargetRejectsUnsafeRef(t *testing.T) {
	srv := newTestServer(t)
	// Whether or not docker is present, an unsafe/absent ref must not scan.
	code, body := postJSON(t, srv, "/v1/sbom", `{"type":"docker","location":"--output=/etc/passwd"}`)
	if code == http.StatusOK {
		t.Errorf("docker scan with an unsafe ref must not succeed: %v", body)
	}
}

func TestComplianceEndpoint(t *testing.T) {
	srv := newTestServer(t)
	code, body := postJSON(t, srv, "/v1/compliance", `{"type":"dockerfile","content":"FROM ubuntu:latest\n"}`)
	if code != http.StatusOK {
		t.Fatalf("/v1/compliance = %d, want 200 (%v)", code, body)
	}
	cov, _ := body["coverage"].([]any)
	if len(cov) == 0 {
		t.Errorf("/v1/compliance returned no framework coverage")
	}
}

// newTestServer builds a server over the real module registry. Constructing it
// exercises route registration — the regression guard for the class of bug
// where a new route (e.g. a method-agnostic /mcp) conflicts with the "GET /"
// catch-all and panics inside New at process start.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("server.New panicked during route registration: %v", r)
		}
	}()
	return New(modules.Default())
}

func TestRoutesRegisterWithoutPanic(t *testing.T) {
	newTestServer(t) // panic → fail, via the deferred recover above
}

func TestCoreEndpoints(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{"healthz", "GET", "/healthz", "", http.StatusOK},
		{"modules", "GET", "/v1/modules", "", http.StatusOK},
		{"web-root", "GET", "/", "", http.StatusOK},
		{"scan-dockerfile", "POST", "/v1/scan", `{"type":"dockerfile","content":"FROM ubuntu:latest\n"}`, http.StatusOK},
		{"mcp-post", "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s = %d, want %d (body: %s)", tc.method, tc.path, rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestModulesEndpointListsRegisteredModules(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/v1/modules", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	var mods []moduleInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &mods); err != nil {
		t.Fatalf("modules response is not valid JSON: %v", err)
	}
	// Every built-in module must be advertised; guard against a registry that
	// silently loses a module.
	if len(mods) != len(modules.Default().All()) {
		t.Errorf("advertised %d modules, registry has %d", len(mods), len(modules.Default().All()))
	}
	byName := map[string]bool{}
	for _, m := range mods {
		byName[m.Name] = true
	}
	for _, want := range []string{"dockerfile", "sbom", "vuln", "secrets", "policy", "runtime"} {
		if !byName[want] {
			t.Errorf("module %q not advertised over /v1/modules", want)
		}
	}
}

func TestMountStoreAddsRoutesWithoutPanic(t *testing.T) {
	srv := newTestServer(t)
	if err := srv.MountStore(t.TempDir()); err != nil {
		t.Fatalf("MountStore: %v", err)
	}
	// The server must still answer core routes after the store API is mounted.
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("healthz after MountStore = %d, want 200", rec.Code)
	}
}

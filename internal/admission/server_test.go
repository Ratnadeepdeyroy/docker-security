package admission

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "admission.policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.CompileBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	rv := NewReviewer(eng, WithClock(func() time.Time { return fixedNow }))
	return httptest.NewServer(NewServer(rv, nil))
}

func postValidate(t *testing.T, srv *httptest.Server, body []byte) *AdmissionResponse {
	t.Helper()
	resp, err := http.Post(srv.URL+"/validate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /validate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	var ar AdmissionReview
	if err := json.Unmarshal(data, &ar); err != nil {
		t.Fatalf("decode response: %v\n%s", err, data)
	}
	if ar.Response == nil {
		t.Fatal("response review has no Response")
	}
	return ar.Response
}

func TestServerValidateDeniesPrivileged(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	body, _ := os.ReadFile(filepath.Join("testdata", "review-privileged.json"))
	resp := postValidate(t, srv, body)
	if resp.Allowed {
		t.Fatal("privileged pod must be denied over HTTP")
	}
	if resp.UID != "req-privileged-001" {
		t.Fatalf("UID = %q", resp.UID)
	}
}

func TestServerValidateAllowsCompliant(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	body, _ := os.ReadFile(filepath.Join("testdata", "review-compliant.json"))
	if resp := postValidate(t, srv, body); !resp.Allowed {
		t.Fatalf("compliant pod must be allowed; status %+v", resp.Status)
	}
}

func TestServerValidateFailsClosedOnGarbage(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	// An undecodable body must still yield a 200 AdmissionReview that denies.
	resp := postValidate(t, srv, []byte(`{"this is": not valid json`))
	if resp.Allowed {
		t.Fatal("garbage body must fail closed (deny)")
	}
}

func TestServerHealthEndpoints(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}
}

func TestServerRejectsWrongMethod(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	// Method-based routing: GET /validate is not allowed.
	resp, err := http.Get(srv.URL + "/validate")
	if err != nil {
		t.Fatalf("GET /validate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /validate = %d, want 405", resp.StatusCode)
	}
}

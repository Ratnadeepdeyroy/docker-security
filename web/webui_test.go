package web

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandlerServesDashboard proves the assets embed and that the served page is
// the security console wired to the live analysis endpoints. If the embed path
// or a key endpoint reference regresses, this fails.
func TestHandlerServesDashboard(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"container security console", "docker-security",
		"/healthz", "/v1/modules", "/v1/scan", "/v1/sbom", "/v1/compliance",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	// It must be fully self-contained: no external resource is *loaded* (offline).
	// (Example URLs inside placeholder text are fine — we check load patterns.)
	for _, forbidden := range []string{`src="http`, `src='http`, `href="http`, `href='http`, "@import", "//unpkg", "googleapis", "cdnjs", "https://cdn"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("dashboard loads external resource %q (must be offline)", forbidden)
		}
	}
}

func TestHandlerServesIndexAtRoot(t *testing.T) {
	// http.FileServer serves index.html for "/" (and 301-redirects "/index.html"
	// to "/"), so we assert on the root path.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("root status %d", w.Code)
	}
	data, _ := io.ReadAll(w.Body)
	if len(data) < 1000 {
		t.Errorf("dashboard suspiciously small: %d bytes", len(data))
	}
}

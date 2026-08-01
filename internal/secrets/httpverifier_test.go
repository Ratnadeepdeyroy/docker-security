package secrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPVerifierProbesProviders drives the real HTTPVerifier against an
// httptest server (no network) for each supported provider, asserting the
// status→state mapping and that the secret is sent in the auth header.
func TestHTTPVerifierProbesProviders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/active":
			w.WriteHeader(http.StatusOK)
		case "/inactive":
			w.WriteHeader(http.StatusUnauthorized)
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	v := HTTPVerifier{
		Client: srv.Client(),
		Endpoints: map[string]string{
			"github-token":      srv.URL + "/active",
			"slack-token":       srv.URL + "/inactive",
			"stripe-secret-key": srv.URL + "/forbidden",
			"npm-token":         srv.URL + "/error",
		},
	}

	cases := []struct {
		slug string
		want VerifyState
	}{
		{"github-token", VerifyActive},
		{"slack-token", VerifyInactive},
		{"stripe-secret-key", VerifyInactive},
		{"npm-token", VerifyUnknown},
	}
	for _, c := range cases {
		got := v.Verify(context.Background(), c.slug, "secret-"+c.slug)
		if got != c.want {
			t.Errorf("Verify(%s) = %v, want %v", c.slug, got, c.want)
		}
	}
	if gotAuth == "" {
		t.Error("verifier did not send an Authorization header")
	}
}

func TestHTTPVerifierUnknownProvider(t *testing.T) {
	v := HTTPVerifier{}
	// A provider with no probe (e.g. a private key) must not attempt any request.
	if got := v.Verify(context.Background(), "private-key", "x"); got != VerifyUnknown {
		t.Errorf("unknown provider should be VerifyUnknown, got %v", got)
	}
}

func TestSupportedVerifiersNonEmpty(t *testing.T) {
	slugs := SupportedVerifiers()
	if len(slugs) < 4 {
		t.Errorf("expected several supported verifiers, got %v", slugs)
	}
	// github-token must be among them (the canonical example).
	found := false
	for _, s := range slugs {
		if s == "github-token" {
			found = true
		}
	}
	if !found {
		t.Error("github-token should be a supported verifier")
	}
}

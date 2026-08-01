package admission

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// --- ValidatingWebhook HTTP server -----------------------------------------
//
// The server exposes the three endpoints a Kubernetes ValidatingWebhook needs:
// /validate for the AdmissionReview exchange, and /healthz + /readyz for the
// probes that let the platform take the webhook out of rotation cleanly. It is a
// thin transport shell over the Reviewer, which holds all the decision logic.
//
// Failure-policy note (documented for the operator, enforced by the manifest):
// the webhook should be registered with failurePolicy: Fail and a short
// timeoutSeconds, so that if this server is unreachable the API server itself
// rejects the request. That is the cluster-side fail-closed; the Reviewer is the
// server-side fail-closed (a parse or eval error denies unless --fail-open).

// maxBodyBytes bounds a request body so a hostile or runaway AdmissionReview
// cannot exhaust server memory. Admission objects are small; 3 MiB is generous.
const maxBodyBytes = 3 << 20

// Server is the webhook HTTP handler.
type Server struct {
	reviewer *Reviewer
	log      *slog.Logger
	mux      *http.ServeMux
}

// NewServer builds a webhook server over a Reviewer. A nil logger discards logs.
func NewServer(rv *Reviewer, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{reviewer: rv, log: log, mux: http.NewServeMux()}
	// Method+pattern routing (Go 1.22+) rejects the wrong verb for free.
	s.mux.HandleFunc("POST /validate", s.handleValidate)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleHealth)
	return s
}

// ServeHTTP satisfies http.Handler so the server drops straight into
// http.ListenAndServe or an httptest.Server.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// handleValidate runs the AdmissionReview exchange. It always answers 200 with a
// valid AdmissionReview: the allow/deny verdict lives in the body, so even a
// malformed request yields a well-formed, fail-closed denial rather than an HTTP
// error the API server would treat per failurePolicy.
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.log.Warn("read admission body", "error", err)
		s.writeReview(w, s.reviewer.Review(&AdmissionReview{}))
		return
	}

	var ar AdmissionReview
	if err := json.Unmarshal(body, &ar); err != nil {
		s.log.Warn("decode admission review", "error", err)
		// Fail closed on an undecodable review: no UID to echo, verdict is deny.
		s.writeReview(w, s.reviewer.Review(&AdmissionReview{}))
		return
	}

	resp := s.reviewer.Review(&ar)
	if resp.Response != nil {
		s.log.Info("admission decision",
			"uid", resp.Response.UID,
			"allowed", resp.Response.Allowed,
			"decision", resp.Response.AuditAnnotations["docker-security.policy/decision"])
	}
	s.writeReview(w, resp)
}

// writeReview serializes an AdmissionReview response.
func (s *Server) writeReview(w http.ResponseWriter, ar *AdmissionReview) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ar); err != nil {
		s.log.Error("encode admission response", "error", err)
	}
}

// handleHealth answers liveness/readiness probes.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

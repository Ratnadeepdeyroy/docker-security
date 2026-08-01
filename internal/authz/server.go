package authz

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// Docker's authorization-plugin wire contract. The daemon POSTs an AuthZReq
// before a request is executed and an AuthZRes after; a plugin implementing the
// pre-request hook is sufficient to block dangerous calls. See
// https://docs.docker.com/engine/extend/plugins_authorization/.

const maxBodyBytes = 4 << 20 // 4 MiB cap on a proxied request body

// authZReq mirrors the fields Docker sends. RequestBody is base64-encoded.
type authZReq struct {
	RequestMethod string `json:"RequestMethod"`
	RequestURI    string `json:"RequestUri"`
	RequestBody   string `json:"RequestBody"`
}

// authZRes is the plugin response Docker expects.
type authZRes struct {
	Allow bool   `json:"Allow"`
	Msg   string `json:"Msg,omitempty"`
	Err   string `json:"Err,omitempty"`
}

// Server adapts the pure Policy to Docker's HTTP plugin protocol.
type Server struct {
	policy *Policy
	log    *slog.Logger
	mux    *http.ServeMux
}

// NewServer builds a plugin HTTP server for a policy.
func NewServer(p *Policy, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{policy: p, log: log, mux: http.NewServeMux()}
	// Docker calls the plugin activation handshake first, then the AuthZ hooks.
	s.mux.HandleFunc("/Plugin.Activate", s.handleActivate)
	s.mux.HandleFunc("/AuthZPlugin.AuthZReq", s.handleReq)
	s.mux.HandleFunc("/AuthZPlugin.AuthZRes", s.handleRes)
	return s
}

// ServeHTTP lets the server drop into http.Serve or httptest.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// handleActivate answers the plugin handshake, declaring the authz capability.
func (s *Server) handleActivate(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string][]string{"Implements": {"authz"}})
}

// handleReq is the pre-request authorization hook — the enforceable gate.
func (s *Server) handleReq(w http.ResponseWriter, r *http.Request) {
	var req authZReq
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, authZRes{Allow: false, Err: "malformed AuthZReq"})
		return
	}
	body, err := base64.StdEncoding.DecodeString(req.RequestBody)
	if err != nil {
		body = nil // absent/empty bodies are common; treat undecodable as empty
	}

	d := s.policy.Evaluate(Request{Method: req.RequestMethod, URI: req.RequestURI, Body: body})
	if d.Allow {
		s.log.Info("authz allow", "method", req.RequestMethod, "uri", req.RequestURI)
		writeJSON(w, authZRes{Allow: true, Msg: d.Msg})
		return
	}
	s.log.Warn("authz deny", "method", req.RequestMethod, "uri", req.RequestURI, "rule", d.Rule, "reason", d.Reason)
	writeJSON(w, authZRes{Allow: false, Msg: d.Reason, Err: d.Reason})
}

// handleRes is the post-response hook. We do not mutate responses, so we always
// allow — the pre-request hook already enforced policy.
func (s *Server) handleRes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, authZRes{Allow: true})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

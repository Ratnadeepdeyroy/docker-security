// Package server is the HTTP/web frontend. Like the CLI, it is a thin adapter
// over the shared engine, so any connector (CI, webhook, UI) can drive the same
// analysis over HTTP.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
	"github.com/Ratnadeepdeyroy/docker-security/internal/dockercli"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/mcp"
	"github.com/Ratnadeepdeyroy/docker-security/internal/report"
	sbomlib "github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
	"github.com/Ratnadeepdeyroy/docker-security/internal/store"
	"github.com/Ratnadeepdeyroy/docker-security/web"
)

// Server exposes the engine over HTTP.
type Server struct {
	reg *engine.Registry
	eng *engine.Engine
	mux *http.ServeMux
}

// New builds an HTTP handler backed by the given module registry.
func New(reg *engine.Registry) *Server {
	s := &Server{reg: reg, eng: engine.New(reg), mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /v1/modules", s.handleModules)
	s.mux.HandleFunc("POST /v1/scan", s.handleScan)
	s.mux.HandleFunc("POST /v1/sbom", s.handleSBOM)
	s.mux.HandleFunc("POST /v1/compliance", s.handleCompliance)
	s.mux.HandleFunc("GET /v1/docker/images", s.handleDockerImages)
	s.mux.HandleFunc("GET /v1/docker/containers", s.handleDockerContainers)
	// Agent-native interface: the MCP server exposes the registry to AI agents
	// (Phase 9). It needs no store to answer capability/scan/explain calls.
	// Register with explicit methods so /mcp does not collide with the "GET /"
	// catch-all below (Go 1.22 ServeMux rejects a method-agnostic /mcp against
	// a method-specific GET /).
	mcpHandler := mcp.New(s.reg).HTTPHandler()
	s.mux.Handle("POST /mcp", mcpHandler)
	s.mux.Handle("GET /mcp", mcpHandler)
	// Catch-all: serve the embedded web dashboard. More specific patterns above
	// take precedence in Go's ServeMux, so API routes are unaffected.
	s.mux.Handle("GET /", web.Handler())
}

// MountStore opens a persistent scan-result store at dir and registers its
// query API (inventory, blast-radius, trends) on the server. Called by
// `dsecrat serve --store DIR`; without it the server is stateless.
func (s *Server) MountStore(dir string) error {
	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	store.NewAPI(st, s.eng).Register(s.mux)
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "tool": "docker-security"})
}

type moduleInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
}

func (s *Server) handleModules(w http.ResponseWriter, _ *http.Request) {
	var out []moduleInfo
	for _, m := range s.reg.All() {
		out = append(out, moduleInfo{Name: m.Name(), Description: m.Description(), Domains: m.Domains()})
	}
	writeJSON(w, http.StatusOK, out)
}

type scanRequest struct {
	Type       string   `json:"type"`
	Location   string   `json:"location"`
	Content    string   `json:"content"`
	Modules    []string `json:"modules"`
	Format     string   `json:"format"`
	Frameworks []string `json:"frameworks"`
}

// targetFromReq builds an analysis target from a request, returning a cleanup
// func the caller must defer. An explicit type wins, else it is detected;
// inline content is preferred, else a Dockerfile is read from disk. The special
// type "docker" resolves a local image *reference* by `docker save`-ing it to a
// temp tar (auto-detected local images, or a ref the user pasted) — the cleanup
// removes that tar.
func (s *Server) targetFromReq(ctx context.Context, req scanRequest) (*engine.Target, func(), error) {
	noop := func() {}

	// Explicit docker image reference (or Docker Hub / registry URL).
	if req.Type == "docker" {
		return s.dockerTarget(ctx, req.Location)
	}

	// Auto-detect: inline content is a Dockerfile; an on-disk path is inspected;
	// otherwise, if it parses as an image reference/URL, treat it as a docker
	// image (pull-if-needed + save) so pasting `ubuntu:latest` or a hub URL works.
	if req.Type == "" && req.Content == "" && req.Location != "" {
		if _, err := os.Stat(req.Location); err != nil {
			if _, ok := dockercli.NormalizeRef(req.Location); ok {
				return s.dockerTarget(ctx, req.Location)
			}
		}
	}

	tt := engine.TargetType(req.Type)
	if tt == "" {
		if req.Location != "" {
			tt = engine.DetectType(req.Location)
		} else {
			tt = engine.TargetDockerfile
		}
	}
	target := &engine.Target{Type: tt, Location: req.Location, Metadata: map[string]string{}}
	switch {
	case req.Content != "":
		target.Content = []byte(req.Content)
	case tt == engine.TargetDockerfile && req.Location != "":
		t, err := engine.NewDockerfileTarget(req.Location)
		if err != nil {
			return nil, noop, err
		}
		target = t
	}
	return target, noop, nil
}

// dockerTarget resolves an image reference (or Docker Hub / registry URL) into a
// scannable target: it normalizes the input, pulls the image if it is not
// already local, and `docker save`s it to a temp tar (cleaned up by the caller).
func (s *Server) dockerTarget(ctx context.Context, input string) (*engine.Target, func(), error) {
	noop := func() {}
	ref, ok := dockercli.NormalizeRef(input)
	if !ok {
		return nil, noop, errText(fmt.Sprintf("%q is not an image reference — paste an image like \"ubuntu:latest\" or a Docker Hub URL (https://hub.docker.com/_/ubuntu), or a docker-save tar / OCI dir / filesystem path", input))
	}
	if !dockercli.Available() {
		return nil, noop, errText(fmt.Sprintf("%q looks like the image %q, but Docker is not available on this host — install/start Docker, or scan a docker-save tar / OCI layout dir / filesystem path instead", input, ref))
	}
	if err := dockercli.EnsureLocal(ctx, ref); err != nil {
		return nil, noop, errText("could not obtain image " + ref + ": " + err.Error())
	}
	f, err := os.CreateTemp("", "dsecrat-img-*.tar")
	if err != nil {
		return nil, noop, err
	}
	tar := f.Name()
	f.Close()
	cleanup := func() { os.Remove(tar) }
	if err := dockercli.Save(ctx, ref, tar); err != nil {
		cleanup()
		return nil, noop, err
	}
	return &engine.Target{Type: engine.TargetImage, Location: tar, Metadata: map[string]string{"docker.ref": ref}}, cleanup, nil
}

// errText is a tiny helper to build an error from a string without importing errors.
func errText(msg string) error { return &simpleErr{msg} }

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }

// handleDockerImages lists images present on the host (empty when docker absent).
func (s *Server) handleDockerImages(w http.ResponseWriter, r *http.Request) {
	if !dockercli.Available() {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "images": []any{}})
		return
	}
	imgs, err := dockercli.Images(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": true, "images": []any{}, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "images": imgs})
}

// handleDockerContainers lists containers on the host.
func (s *Server) handleDockerContainers(w http.ResponseWriter, r *http.Request) {
	if !dockercli.Available() {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "containers": []any{}})
		return
	}
	cs, err := dockercli.Containers(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": true, "containers": []any{}, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "containers": cs})
}

// handleSBOM generates a Software Bill of Materials for the target. With
// ?format=cyclonedx|spdx (or a "format" body field) it returns the standardized
// document; otherwise it returns the native SBOM model as JSON for the UI.
func (s *Server) handleSBOM(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}
	target, cleanup, err := s.targetFromReq(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	defer cleanup()
	doc, err := sbomlib.Generate(r.Context(), target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if f := req.Format; f == "cyclonedx" || f == "spdx" {
		meta := sbomlib.DocMeta{
			Timestamp:   time.Now().UTC(),
			Serial:      "urn:uuid:" + sbomlib.DeterministicUUID(doc.Source.Name+"|"+doc.Source.ImageDigest),
			ToolName:    "docker-security",
			ToolVersion: toolVersion,
		}
		data, err := sbomlib.Marshal(doc, sbomlib.Format(f), meta)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

// handleCompliance runs the engine and maps findings onto the framework control
// packs, returning the full compliance report (dispositions + coverage input).
func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}
	target, cleanup, err := s.targetFromReq(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	defer cleanup()
	cat, err := compliance.LoadEmbeddedPacks()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	frameworks := req.Frameworks
	if len(frameworks) == 0 {
		frameworks = cat.Frameworks()
	}
	rep := s.eng.Run(r.Context(), target)
	cr := compliance.RunPacks(cat, frameworks, rep, compliance.RunOptions{
		Now: time.Now().UTC(), ToolVersion: toolVersion, Target: target.Location,
	})
	writeJSON(w, http.StatusOK, map[string]any{"report": cr, "coverage": compliance.Coverage(cr)})
}

// toolVersion labels evidence/SBOM metadata produced over HTTP.
const toolVersion = "0.1.0"

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return
	}

	target, cleanup, err := s.targetFromReq(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	defer cleanup()

	rep := s.eng.Run(r.Context(), target, req.Modules...)

	switch req.Format {
	case "", "json":
		writeJSON(w, http.StatusOK, rep)
	default:
		f, err := report.Get(req.Format)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = f.Format(w, rep)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

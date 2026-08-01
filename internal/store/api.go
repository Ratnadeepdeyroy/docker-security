package store

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- HTTP API ------------------------------------------------------------
//
// API exposes the store's read queries — and one scan-and-persist write — as
// versioned HTTP endpoints. It is a frontend adapter, mirroring the existing
// server package: it owns no analysis logic, only translation between HTTP and
// the engine/store. The master mounts it onto the server's mux (see NOTES.md);
// nothing here edits server.go.

// maxScanBody bounds an inbound scan request so a hostile client cannot stream
// unbounded content into memory.
const maxScanBody = 8 << 20 // 8 MiB

// API serves store queries and (optionally) triggers scans that it persists.
type API struct {
	store *Store
	eng   *engine.Engine // may be nil: read-only API without scan-trigger
	// now is injected for deterministic tests; production uses time.Now.
	now func() time.Time
}

// NewAPI builds a store API. Pass a non-nil engine to enable POST /v1/scans;
// pass nil for a read-only inventory API.
func NewAPI(s *Store, eng *engine.Engine) *API {
	return &API{store: s, eng: eng, now: func() time.Time { return time.Now().UTC() }}
}

// Register wires every store route onto mux. The master calls this once from
// server.go's routes() when the store is enabled.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/scans", a.handleListScans)
	mux.HandleFunc("GET /v1/scans/{id}", a.handleGetScan)
	mux.HandleFunc("POST /v1/scans", a.handleCreateScan)
	mux.HandleFunc("GET /v1/inventory", a.handleInventory)
	mux.HandleFunc("GET /v1/inventory/component", a.handleComponent)
	mux.HandleFunc("GET /v1/findings", a.handleFindings)
	mux.HandleFunc("GET /v1/trends", a.handleTrends)
}

func (a *API) handleListScans(w http.ResponseWriter, _ *http.Request) {
	type row struct {
		ID         string         `json:"id"`
		Image      string         `json:"image"`
		Digest     string         `json:"digest,omitempty"`
		TargetType string         `json:"target_type,omitempty"`
		RecordedAt time.Time      `json:"recorded_at"`
		Owner      string         `json:"owner,omitempty"`
		Counts     map[string]int `json:"counts"`
		Components int            `json:"components"`
	}
	scans := a.store.Scans()
	out := make([]row, 0, len(scans))
	for _, sc := range scans {
		out = append(out, row{
			ID: sc.ID, Image: sc.Image, Digest: sc.Digest, TargetType: sc.TargetType,
			RecordedAt: sc.RecordedAt, Owner: sc.Labels["owner"],
			Counts: severityCounts(sc.Report), Components: len(sc.Components),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleGetScan(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("scan not found"))
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (a *API) handleInventory(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.store.Inventory())
}

func (a *API) handleComponent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	matches := a.store.QueryComponent(ComponentQuery{
		Name:           q.Get("name"),
		Version:        q.Get("version"),
		PURL:           q.Get("purl"),
		LatestPerImage: parseBool(q.Get("latest")),
	})
	writeJSON(w, http.StatusOK, struct {
		Query   string           `json:"query"`
		Count   int              `json:"count"`
		Matches []ComponentMatch `json:"matches"`
	}{Query: q.Get("name"), Count: len(matches), Matches: matches})
}

func (a *API) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fq := FindingQuery{
		Image:  q.Get("image"),
		Module: q.Get("module"),
		RuleID: q.Get("rule"),
		Owner:  q.Get("owner"),
	}
	if s := q.Get("min_severity"); s != "" {
		fq.MinSeverity = engine.ParseSeverity(s)
	}
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			fq.Since = t
		}
	}
	writeJSON(w, http.StatusOK, a.store.QueryFindings(fq))
}

func (a *API) handleTrends(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.Trends(r.URL.Query().Get("image")))
}

// scanRequest mirrors the server's scan body plus store metadata.
type scanRequest struct {
	Type     string            `json:"type"`
	Location string            `json:"location"`
	Content  string            `json:"content"`
	Image    string            `json:"image"`
	Modules  []string          `json:"modules"`
	Labels   map[string]string `json:"labels"`
	Persist  *bool             `json:"persist"` // default true
	SBOM     *bool             `json:"sbom"`    // default true (best-effort)
}

// handleCreateScan runs a scan and, unless persist=false, stores it with its
// SBOM inventory. This is what the dashboard's "trigger scan" button calls.
func (a *API) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	if a.eng == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("scan-trigger disabled: no engine configured"))
		return
	}
	var req scanRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxScanBody))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid JSON body: "+err.Error()))
		return
	}

	target, err := a.buildTarget(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}

	withSBOM := req.SBOM == nil || *req.SBOM
	sc := RunAndBuild(r.Context(), a.eng, target, req.Modules, req.Image, req.Labels, withSBOM, a.now())

	persist := req.Persist == nil || *req.Persist
	var id string
	if persist {
		if id, err = a.store.Put(sc); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
	} else {
		sc.normalize()
		id = sc.ID
	}

	writeJSON(w, http.StatusOK, struct {
		ScanID     string         `json:"scan_id"`
		Persisted  bool           `json:"persisted"`
		Components int            `json:"components"`
		Report     *engine.Report `json:"report"`
	}{ScanID: id, Persisted: persist, Components: len(sc.Components), Report: sc.Report})
}

// buildTarget turns a request into an engine.Target, mirroring the server's
// logic so behaviour is consistent across the two write paths.
func (a *API) buildTarget(req scanRequest) (*engine.Target, error) {
	tt := engine.TargetType(req.Type)
	if tt == "" {
		if req.Location != "" {
			tt = engine.DetectType(req.Location)
		} else {
			tt = engine.TargetDockerfile
		}
	}
	target := &engine.Target{Type: tt, Location: req.Location, Metadata: map[string]string{}}
	if req.Content != "" {
		target.Content = []byte(req.Content)
		return target, nil
	}
	if tt == engine.TargetDockerfile && req.Location != "" {
		return engine.NewDockerfileTarget(req.Location)
	}
	return target, nil
}

// --- helpers -------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

// parseBool parses a permissive truthy query value.
func parseBool(s string) bool {
	b, _ := strconv.ParseBool(strings.TrimSpace(s))
	return b
}

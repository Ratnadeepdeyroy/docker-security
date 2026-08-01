package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// --- In-memory registry -----------------------------------------------------
//
// MemoryRegistry is a minimal but spec-faithful OCI distribution server that
// lives entirely in memory. It exists so the whole supply-chain suite — sign,
// push, pull, referrers, verify — runs offline against a real HTTP surface, not
// a mock: the same Client code path exercised in production is exercised in
// tests. It implements the subset of the v2 API the client uses (manifests,
// blobs via monolithic upload, tags, and the OCI 1.1 referrers endpoint). It is
// deliberately not hardened for hostile multi-tenant use — it is a test/demo
// fixture, and the package doc says so.

// MemoryRegistry is an http.Handler implementing the registry v2 API in memory.
// The zero value is not ready; use NewMemoryRegistry. Safe for concurrent use.
type MemoryRegistry struct {
	mu    sync.Mutex
	repos map[string]*memRepo
	// requireAuth, when true, makes every data request 401 unless a bearer/basic
	// credential is present — used to test the client's auth handling and the
	// posture module's "anonymous access" detection.
	requireAuth bool
}

type memRepo struct {
	blobs     map[string][]byte // digest -> bytes
	manifests map[string]memManifest
	tags      map[string]string // tag -> digest
}

type memManifest struct {
	bytes     []byte
	mediaType string
}

// NewMemoryRegistry returns an empty in-memory registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{repos: map[string]*memRepo{}}
}

// SetRequireAuth toggles whether the registry demands authentication. With it
// on, unauthenticated data requests get 401 (no token endpoint is provided, so
// this models a registry that forbids anonymous access).
func (m *MemoryRegistry) SetRequireAuth(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requireAuth = v
}

func (m *MemoryRegistry) repo(name string) *memRepo {
	r, ok := m.repos[name]
	if !ok {
		r = &memRepo{blobs: map[string][]byte{}, manifests: map[string]memManifest{}, tags: map[string]string{}}
		m.repos[name] = r
	}
	return r
}

// ServeHTTP routes distribution API requests.
func (m *MemoryRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "{}")
		return
	}
	// The /v2/ ping is always allowed; data endpoints honor requireAuth.
	if m.authRequired() && r.Header.Get("Authorization") == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://memory/token",service="memory"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	name, kind, arg, ok := splitAPIPath(r.URL.Path)
	if !ok || name == "" {
		http.NotFound(w, r)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	switch kind {
	case "manifests":
		m.handleManifest(w, r, name, arg)
	case "blobs-uploads":
		m.handleUpload(w, r, name, arg)
	case "blobs":
		m.handleBlob(w, r, name, arg)
	case "referrers":
		m.handleReferrers(w, r, name, arg)
	case "tags":
		m.handleTags(w, name)
	default:
		http.NotFound(w, r)
	}
}

func (m *MemoryRegistry) authRequired() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requireAuth
}

// splitAPIPath decomposes /v2/<name>/<kind>/<arg>, tolerating multi-segment
// repository names. Order matters: the more specific markers are tried first.
func splitAPIPath(path string) (name, kind, arg string, ok bool) {
	p := strings.TrimPrefix(path, "/v2/")
	markers := []struct{ marker, kind string }{
		{"/manifests/", "manifests"},
		{"/blobs/uploads/", "blobs-uploads"},
		{"/referrers/", "referrers"},
		{"/blobs/", "blobs"},
		{"/tags/list", "tags"},
	}
	for _, mk := range markers {
		if i := strings.Index(p, mk.marker); i >= 0 {
			return p[:i], mk.kind, p[i+len(mk.marker):], true
		}
	}
	return "", "", "", false
}

func (m *MemoryRegistry) handleManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	repo := m.repo(name)
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, maxManifestBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		digest := Digest(body)
		mt := r.Header.Get("Content-Type")
		if mt == "" {
			mt = MediaTypeOCIManifest
		}
		repo.manifests[digest] = memManifest{bytes: body, mediaType: mt}
		if !strings.HasPrefix(ref, "sha256:") {
			repo.tags[ref] = digest
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, digest))
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet, http.MethodHead:
		digest := ref
		if !strings.HasPrefix(ref, "sha256:") {
			d, ok := repo.tags[ref]
			if !ok {
				http.Error(w, "manifest unknown", http.StatusNotFound)
				return
			}
			digest = d
		}
		mm, ok := repo.manifests[digest]
		if !ok {
			http.Error(w, "manifest unknown", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", mm.mediaType)
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Length", strconv.Itoa(len(mm.bytes)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(mm.bytes)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *MemoryRegistry) handleUpload(w http.ResponseWriter, r *http.Request, name, arg string) {
	repo := m.repo(name)
	switch r.Method {
	case http.MethodPost:
		// Begin an upload session. arg is empty ("/blobs/uploads/").
		id := fmt.Sprintf("u%d", len(repo.blobs)+1)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, id))
		w.Header().Set("Range", "0-0")
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		// Complete the monolithic upload; the digest is in the query.
		digest := r.URL.Query().Get("digest")
		body, err := io.ReadAll(io.LimitReader(r.Body, maxManifestBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if digest == "" {
			digest = Digest(body)
		}
		if got := Digest(body); got != digest {
			http.Error(w, "digest mismatch on upload", http.StatusBadRequest)
			return
		}
		repo.blobs[digest] = body
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *MemoryRegistry) handleBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
	repo := m.repo(name)
	data, ok := repo.blobs[digest]
	if !ok {
		http.Error(w, "blob unknown", http.StatusNotFound)
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// handleReferrers computes the referrers index on the fly by scanning stored
// manifests for a subject matching the requested digest — exactly what a
// conformant registry returns from GET /v2/<name>/referrers/<digest>.
func (m *MemoryRegistry) handleReferrers(w http.ResponseWriter, r *http.Request, name, subject string) {
	repo := m.repo(name)
	filter := r.URL.Query().Get("artifactType")
	idx := Index{SchemaVersion: 2, MediaType: MediaTypeOCIIndex}
	for digest, mm := range repo.manifests {
		var man Manifest
		if err := json.Unmarshal(mm.bytes, &man); err != nil {
			continue
		}
		if man.Subject == nil || man.Subject.Digest != subject {
			continue
		}
		if filter != "" && man.ArtifactType != filter {
			continue
		}
		idx.Manifests = append(idx.Manifests, Descriptor{
			MediaType:    mm.mediaType,
			Digest:       digest,
			Size:         int64(len(mm.bytes)),
			ArtifactType: man.ArtifactType,
			Annotations:  man.Annotations,
		})
	}
	sortDescriptors(idx.Manifests)
	body, _ := json.Marshal(idx)
	w.Header().Set("Content-Type", MediaTypeOCIIndex)
	if filter != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func (m *MemoryRegistry) handleTags(w http.ResponseWriter, name string) {
	repo := m.repo(name)
	tags := make([]string, 0, len(repo.tags))
	for t := range repo.tags {
		tags = append(tags, t)
	}
	sortStrings(tags)
	body, _ := json.Marshal(struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{Name: name, Tags: tags})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// sortDescriptors/sortStrings keep responses deterministic (map iteration is
// random), which matters for reproducible tests and golden output.
func sortDescriptors(ds []Descriptor) {
	for i := 1; i < len(ds); i++ {
		for j := i; j > 0 && ds[j-1].Digest > ds[j].Digest; j-- {
			ds[j-1], ds[j] = ds[j], ds[j-1]
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// Package store persists scan results and SBOM inventory so the platform can
// answer questions that a single stateless scan cannot: "which of the images we
// have ever scanned contain component X at version Y?" (the blast-radius query a
// team runs the morning a zero-day drops), "is our critical count trending up?",
// and "who owns the image with the most findings?".
//
// The store is deliberately optional. The CLI and CI paths stay stateless; a
// server enables the store explicitly. It changes nothing about scan *results* —
// it only records the Reports the engine already produced and the SBOM inventory
// that already exists, then indexes them for query.
//
// Two backends share one query core: an in-memory index (NewMemory, used for
// tests and ephemeral runs) and a flat-file JSON backend (Open, one file per
// scan, atomic writes, rebuilt into the index on open). No SQL, no cgo, no
// external driver — a design choice, not a limitation (see NOTES.md).
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Domain model --------------------------------------------------------

// Component is one inventoried package, flattened out of an SBOM for indexing.
// We keep only what blast-radius queries need; the full SBOM lives in the scan's
// Report metadata or can be regenerated. Name/Version are lower-cased on ingest
// so matching is case-insensitive without re-normalizing on every query.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// Scan is one persisted analysis run: the engine Report, the artifact's
// component inventory, and the identity/ownership needed to group and attribute
// it. It is a plain value so it JSON-marshals directly to the file backend.
type Scan struct {
	// ID is a deterministic content hash (see computeID). Re-storing the same
	// image at the same recorded time overwrites rather than duplicates.
	ID         string            `json:"id"`
	Image      string            `json:"image"` // canonical identity for grouping (image ref or path)
	Digest     string            `json:"digest,omitempty"`
	TargetType string            `json:"target_type,omitempty"`
	RecordedAt time.Time         `json:"recorded_at"`
	Labels     map[string]string `json:"labels,omitempty"` // ownership: owner, team, env, …
	Report     *engine.Report    `json:"report"`
	Components []Component       `json:"components,omitempty"`
}

// computeID derives a stable id from the scan's identity, recorded time, and a
// fingerprint of its findings. Deterministic in, deterministic out — no clock or
// randomness — so golden tests and idempotent re-ingest both hold.
func (s *Scan) computeID() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%d\x00", s.Image, s.Digest, s.TargetType, s.RecordedAt.UTC().UnixNano())
	if s.Report != nil {
		for _, f := range s.Report.Findings {
			fmt.Fprintf(h, "%s|%s|%d\x00", f.RuleID, f.Resource, f.Severity)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// normalize fills in the id and lower-cases component match keys. Called on
// every write so both backends store canonical records.
func (s *Scan) normalize() {
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	for i := range s.Components {
		s.Components[i].Name = strings.ToLower(strings.TrimSpace(s.Components[i].Name))
		s.Components[i].Version = strings.TrimSpace(s.Components[i].Version)
	}
	if s.ID == "" {
		s.ID = s.computeID()
	}
}

// --- Store ---------------------------------------------------------------

// Store is a queryable, thread-safe inventory of scans. Construct it with
// NewMemory (ephemeral) or Open (file-backed). All query methods return
// deterministically ordered results.
type Store struct {
	mu      sync.RWMutex
	scans   map[string]*Scan
	backend backend // nil ⇒ memory only
}

// backend is the persistence seam. The file backend is the only implementation;
// memory stores use a nil backend.
type backend interface {
	save(*Scan) error
	load() ([]*Scan, error)
}

// NewMemory returns an ephemeral, in-memory store. Nothing is persisted; ideal
// for tests and for server runs that do not want a data directory.
func NewMemory() *Store {
	return &Store{scans: map[string]*Scan{}}
}

// Put records (or replaces) a scan and returns its id. The scan is copied
// defensively so later caller mutations cannot corrupt the index.
func (s *Store) Put(sc *Scan) (string, error) {
	if sc == nil {
		return "", fmt.Errorf("store: nil scan")
	}
	if sc.Image == "" {
		return "", fmt.Errorf("store: scan has no image identity")
	}
	dup := *sc
	dup.normalize()
	s.mu.Lock()
	s.scans[dup.ID] = &dup
	s.mu.Unlock()
	if s.backend != nil {
		if err := s.backend.save(&dup); err != nil {
			return dup.ID, fmt.Errorf("store: persist scan %s: %w", dup.ID, err)
		}
	}
	return dup.ID, nil
}

// Get returns a scan by id.
func (s *Store) Get(id string) (*Scan, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.scans[id]
	return sc, ok
}

// Scans returns every stored scan, newest first (ties broken by id for
// stability).
func (s *Store) Scans() []*Scan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Scan, 0, len(s.scans))
	for _, sc := range s.scans {
		out = append(out, sc)
	}
	sortScans(out)
	return out
}

// Len reports how many scans are stored.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.scans)
}

// sortScans orders newest-first, then by id, so output is deterministic even
// when two scans share a timestamp.
func sortScans(scs []*Scan) {
	sort.SliceStable(scs, func(i, j int) bool {
		if !scs[i].RecordedAt.Equal(scs[j].RecordedAt) {
			return scs[i].RecordedAt.After(scs[j].RecordedAt)
		}
		return scs[i].ID < scs[j].ID
	})
}

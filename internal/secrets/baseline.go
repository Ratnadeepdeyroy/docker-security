package secrets

import (
	"encoding/json"
	"fmt"
	"os"
)

// --- Baseline / allowlist ---------------------------------------------------
//
// Real repositories carry accepted findings: a test fixture, a rotated key kept
// for history, a false positive that is not worth a code change. Muting the
// whole rule would blind the scanner; muting the whole file is almost as bad.
// A baseline records the exact accepted secrets by fingerprint, with a
// justification, so those specific findings are suppressed while any *new*
// secret — a different fingerprint — still fires. The file is meant to be
// committed and reviewed like code.

// Baseline is a versioned set of accepted findings.
type Baseline struct {
	Version int             `json:"version"`
	Entries []BaselineEntry `json:"entries"`

	// index is the fingerprint set, built once at load for O(1) lookups.
	index map[string]bool
}

// BaselineEntry is a single accepted finding. RuleID and Fingerprint identify
// it exactly; Path, when present, further scopes the acceptance to one
// location. Justification is required in spirit (a baseline without reasons
// rots) and surfaced so reviewers can audit it.
type BaselineEntry struct {
	RuleID        string `json:"rule_id"`
	Fingerprint   string `json:"fingerprint"`
	Path          string `json:"path,omitempty"`
	Justification string `json:"justification"`
}

// LoadBaseline reads and validates a baseline JSON file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %q: %w", path, err)
	}
	return ParseBaseline(data)
}

// ParseBaseline parses baseline JSON from memory. It is separate from
// LoadBaseline so callers (and tests) can supply bytes directly.
func ParseBaseline(data []byte) (*Baseline, error) {
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	b.reindex()
	return &b, nil
}

// reindex (re)builds the fast-lookup key set from Entries.
func (b *Baseline) reindex() {
	b.index = make(map[string]bool, len(b.Entries))
	for _, e := range b.Entries {
		b.index[baselineKey(e.RuleID, e.Fingerprint, e.Path)] = true
	}
}

// Allows reports whether d has been accepted by this baseline. It matches on
// rule + fingerprint, optionally scoped to a path: an unscoped entry accepts the
// secret wherever it appears, a path-scoped entry only at that path.
func (b *Baseline) Allows(d Detection) bool {
	if b == nil {
		return false
	}
	if b.index[baselineKey(d.Code, d.Fingerprint, "")] {
		return true
	}
	return b.index[baselineKey(d.Code, d.Fingerprint, d.Path)]
}

// baselineKey builds the composite lookup key. An empty path yields the
// "anywhere" key; a non-empty path yields the scoped key.
func baselineKey(ruleID, fingerprint, path string) string {
	return ruleID + "\x00" + fingerprint + "\x00" + path
}

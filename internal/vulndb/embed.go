package vulndb

import _ "embed"

// --- Embedded bootstrap snapshot ----------------------------------------

// embeddedDB is a small, committed advisory snapshot so `dsecrat scan` finds real
// vulnerabilities out of the box with zero network access. It is intentionally
// modest: operators refresh and expand it with `dsecrat vuln update`. The
// correctness-critical tests use pinned fixture databases, not this file, so
// growing the snapshot never destabilizes a golden test.
//
//go:embed data/advisories.json
var embeddedDB []byte

// Default loads the embedded bootstrap advisory database.
func Default() (*DB, error) {
	return LoadJSON(embeddedDB)
}

// EmbeddedBytes returns the raw embedded snapshot, for tooling that wants to
// write it to disk as a starting point.
func EmbeddedBytes() []byte { return embeddedDB }

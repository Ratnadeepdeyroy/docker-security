// Package secrets finds credentials embedded in container images, filesystems,
// and Dockerfiles. It is a from-scratch implementation of provider-aware secret
// detection: a data-driven ruleset of provider-specific detectors,
// an entropy fallback, layer-aware image scanning (including content deleted by
// a later whiteout, which stays extractable and is a classic leak), a
// versioned baseline/allowlist, and an opt-in live-verification hook.
//
// Two principles shape the design:
//
//   - Precision is a feature. A noisy secret scanner gets muted, and a muted
//     scanner misses the real leak. The default rule set is high-signal; the
//     broad entropy sweep is gated behind an optional classifier so it never
//     floods the default run.
//   - Values never leave the process. A Detection carries a fingerprint (a
//     truncated SHA-256), a type, a length, and a location — never the secret
//     itself. Even the opt-in verifier receives the raw value transiently and
//     the scanner discards it immediately.
//
// The package is deterministic: given the same bytes it emits the same
// Detections in the same order, with no reliance on the wall clock or a random
// source. Verification (the one network-touching feature) is strictly opt-in
// and injected, so tests never reach the network.
package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// Kind is a coarse category for a detected secret, used for grouping and for
// routing verification. It is intentionally small and stable.
type Kind string

const (
	KindCloud      Kind = "cloud"       // cloud provider keys (AWS, GCP, Azure)
	KindVCS        Kind = "vcs"         // source-forge tokens (GitHub, GitLab)
	KindPrivateKey Kind = "private-key" // PEM private-key blocks
	KindJWT        Kind = "jwt"         // JSON Web Tokens
	KindDatabase   Kind = "database"    // connection strings with credentials
	KindPayment    Kind = "payment"     // payment-processor keys (Stripe, ...)
	KindMessaging  Kind = "messaging"   // Slack, SendGrid, ...
	KindGeneric    Kind = "generic"     // keyword/entropy heuristics
	KindCanary     Kind = "canary"      // a planted honeytoken (not a real leak)
)

// VerifyState records whether a detected secret was checked against its live
// provider. Verification is opt-in; the default is VerifySkipped.
type VerifyState string

const (
	VerifySkipped  VerifyState = "skipped"  // verification not attempted (default)
	VerifyUnknown  VerifyState = "unknown"  // attempted, provider gave no clear answer
	VerifyActive   VerifyState = "active"   // confirmed live — prioritize
	VerifyInactive VerifyState = "inactive" // confirmed dead — likely already rotated
)

// Detection is a single secret found by the scanner. It is deliberately
// value-free: Fingerprint identifies the secret without revealing it, so a
// Detection can be logged, serialized, and diffed safely.
type Detection struct {
	Code        string          // stable engine RuleID, e.g. "DS-RAT-SEC-001"
	Slug        string          // machine-readable detector id, e.g. "aws-access-key-id"
	Kind        Kind            // coarse category
	Severity    engine.Severity // base severity (verification may raise it)
	Fingerprint string          // truncated SHA-256 of the secret value (never the value)
	Entropy     float64         // Shannon entropy of the secret value
	Confidence  string          // "high" | "medium" | "low" — corroboration grade (see confidence.go)
	Length      int             // length of the secret value in bytes
	Path        string          // where it was found (file path, or a pseudo-path)
	Line        int             // 1-based line within the source, 0 if not line-oriented
	Source      Source          // what kind of location Path refers to
	Deleted     bool            // found only in a layer removed by a later whiteout
	LayerIndex  int             // image layer index; -1 for the effective filesystem / non-layer sources
	LayerDigest string          // image layer digest, when known
	Verify      VerifyState     // live-verification result
	Title       string          // human summary, safe to display
	Remediation string          // structured, agent-consumable fix guidance
	References  []string        // CIS/NIST/vendor references

	verifierKey string // internal: which verifier to route through
}

// Source describes what a Detection's Path refers to.
type Source string

const (
	SourceFile         Source = "file"          // a file in a filesystem or flattened image
	SourceDeletedLayer Source = "deleted-layer" // a file present only in a superseded layer
	SourceImageEnv     Source = "image-config-env"
	SourceImageHistory Source = "image-history"
	SourceDockerfile   Source = "dockerfile"
)

// fingerprint returns a short, stable, non-reversible identifier for a secret
// value. We keep only the leading bytes of the digest: enough to distinguish
// and to match against a baseline, not enough to aid brute-forcing.
func fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])[:16]
}

// fingerprintBytes is fingerprint's []byte counterpart: it hashes data
// directly with no string round-trip, for callers (like contentHash in
// image.go) that already hold the bytes and would otherwise pay for a
// []byte->string->[]byte copy just to reach sha256.Sum256. Output format is
// identical to fingerprint's.
func fingerprintBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}

// lineOf returns the 1-based line number of byte offset off within data. It
// is O(off) per call; prefer lineAt with a precomputed newlineOffsets table
// when computing many line numbers against the same data (e.g. one per hit in
// scanFile), since repeated O(off) scans there would be O(hits*filesize).
func lineOf(data []byte, off int) int {
	if off > len(data) {
		off = len(data)
	}
	line := 1
	for i := 0; i < off; i++ {
		if data[i] == '\n' {
			line++
		}
	}
	return line
}

// newlineOffsets returns the byte offsets of every '\n' in data, in ascending
// order. Computing this once per file and reusing it via lineAt turns N
// line-number lookups into a single O(len(data)) pass plus N O(log lines)
// binary searches, instead of N independent O(offset) scans from the start of
// the file.
func newlineOffsets(data []byte) []int {
	var offs []int
	for i, b := range data {
		if b == '\n' {
			offs = append(offs, i)
		}
	}
	return offs
}

// lineAt returns the 1-based line number for byte offset off, given data's
// length and its precomputed, ascending newlineOffsets. It is equivalent to
// lineOf(data, off) but O(log len(newlines)) instead of O(off).
func lineAt(newlines []int, dataLen, off int) int {
	if off > dataLen {
		off = dataLen
	}
	// The line number is 1 + the count of newlines strictly before off; that
	// count is the index of the first newline offset >= off (all offsets
	// before that index are < off, since newlines is sorted ascending).
	n := sort.Search(len(newlines), func(i int) bool { return newlines[i] >= off })
	return n + 1
}

// SortDetections orders detections deterministically so identical input yields
// byte-identical output. The ordering is stable across runs and machines:
// non-deleted before deleted, then by layer, path, line, rule code, and finally
// fingerprint to break any remaining ties.
func SortDetections(ds []Detection) {
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if a.Deleted != b.Deleted {
			return !a.Deleted // live findings first
		}
		if a.LayerIndex != b.LayerIndex {
			return a.LayerIndex < b.LayerIndex
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Fingerprint < b.Fingerprint
	})
}

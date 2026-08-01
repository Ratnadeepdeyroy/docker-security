package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// --- Audit trail ---------------------------------------------------------
//
// Every mutating tool call is recorded here — both the ones we allow and the
// ones we deny because mutations are off. An operator (or an agent's overseer)
// can then answer "what did the agent try to change, and when?". We record a
// digest of the arguments rather than the raw arguments so the trail never
// becomes a place secrets leak into.

// AuditEntry is one recorded mutating-tool attempt.
type AuditEntry struct {
	Time       time.Time `json:"time"`
	Tool       string    `json:"tool"`
	Allowed    bool      `json:"allowed"`
	ArgsDigest string    `json:"args_digest"`
	Note       string    `json:"note,omitempty"`
}

// AuditLog is a thread-safe, in-memory record of mutating-tool attempts.
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
}

// NewAuditLog returns an empty audit log.
func NewAuditLog() *AuditLog { return &AuditLog{} }

// record appends an entry. args is hashed, never stored verbatim.
func (l *AuditLog) record(now time.Time, tool string, allowed bool, args []byte, note string) {
	sum := sha256.Sum256(args)
	l.mu.Lock()
	l.entries = append(l.entries, AuditEntry{
		Time:       now,
		Tool:       tool,
		Allowed:    allowed,
		ArgsDigest: hex.EncodeToString(sum[:])[:16],
		Note:       note,
	})
	l.mu.Unlock()
}

// Entries returns a copy of the audit trail in chronological order.
func (l *AuditLog) Entries() []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

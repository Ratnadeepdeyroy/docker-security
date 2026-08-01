package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// This file implements capture-on-alert forensics with a verifiable chain of
// custody. When a detection fires, the sensor snapshots the triggering event,
// the surrounding event window, and the process tree into a bundle, then seals
// it with a content hash. The hash makes the evidence tamper-evident and
// WORM-friendly: write it once, and anyone can later recompute the digest to
// prove the bytes were not altered. Detection without preserved, trustworthy
// evidence is just noise — this closes that gap.
//
// Everything here is deterministic: the digest is over canonical JSON and the
// capture time comes from event data, never the wall clock, so the same
// detection over the same events always seals to the same digest (golden-testable).

// ForensicBundle is the preserved evidence for one detection.
type ForensicBundle struct {
	RuleSet   string        `json:"ruleset"`
	Detection Detection     `json:"detection"`
	Container ContainerInfo `json:"container"`
	// ProcessTree is the acting process's ancestry chain, root→leaf.
	ProcessTree []string `json:"process_tree,omitempty"`
	// Window is the ordered slice of events preserved around the detection (the
	// daemon's recent-event ring buffer at alert time). Argv is already redacted.
	Window []Event `json:"window"`
	// CapturedUnixNano is the triggering event's time — evidence provenance, not
	// a clock read, so capture is reproducible.
	CapturedUnixNano int64 `json:"captured_unix_nano,omitempty"`
}

// Evidence is a sealed ForensicBundle: the bundle plus a chain-of-custody digest
// over its canonical bytes. Serialize this to durable, write-once storage.
type Evidence struct {
	Algorithm string         `json:"algorithm"` // "sha256"
	Digest    string         `json:"digest"`    // hex sha256 of canonical bundle bytes
	Bundle    ForensicBundle `json:"bundle"`
}

// CaptureForensics seals a detection and its surrounding event window into
// tamper-evident Evidence. window should be the recent events the daemon held
// when the detection fired; it is copied defensively and its argv redacted.
func CaptureForensics(d Detection, window []Event) *Evidence {
	safe := make([]Event, len(window))
	for i, ev := range window {
		ev.Process.Args = redactArgs(ev.Process.Args)
		safe[i] = ev
	}
	bundle := ForensicBundle{
		RuleSet:          RuleSetVersion,
		Detection:        d,
		Container:        d.Container,
		ProcessTree:      append([]string(nil), d.Process.Ancestry...),
		Window:           safe,
		CapturedUnixNano: d.TimeUnixNano,
	}
	digest := digestBundle(bundle)
	return &Evidence{Algorithm: "sha256", Digest: digest, Bundle: bundle}
}

// digestBundle computes the canonical sha256 of a bundle. Canonical = Go's JSON
// encoding, which sorts map keys and is stable field order, so the digest is
// reproducible across runs and machines.
func digestBundle(b ForensicBundle) string {
	data, _ := json.Marshal(b) // ForensicBundle has no un-marshalable fields
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Verify recomputes the digest over the in-memory bundle and reports whether it
// matches the sealed value — the integrity check on an Evidence value.
func (e *Evidence) Verify() bool {
	return e.Algorithm == "sha256" && e.Digest == digestBundle(e.Bundle)
}

// VerifyEvidenceBytes checks an evidence artifact read from disk without needing
// to fully unmarshal the bundle into typed structs. It canonicalizes the raw
// bundle bytes (json.Compact is the inverse of the indentation WriteToDir adds)
// and compares their sha256 to the sealed digest. This is the chain-of-custody
// check a downstream tool runs, and it is robust to pretty-printing and to types
// (like engine.Severity) that marshal but do not unmarshal symmetrically.
func VerifyEvidenceBytes(data []byte) (bool, error) {
	var env struct {
		Algorithm string          `json:"algorithm"`
		Digest    string          `json:"digest"`
		Bundle    json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return false, fmt.Errorf("parse evidence: %w", err)
	}
	if env.Algorithm != "sha256" {
		return false, fmt.Errorf("unsupported digest algorithm %q", env.Algorithm)
	}
	var canonical bytes.Buffer
	if err := json.Compact(&canonical, env.Bundle); err != nil {
		return false, fmt.Errorf("canonicalize bundle: %w", err)
	}
	sum := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(sum[:]) == env.Digest, nil
}

// WriteToDir writes the evidence as a WORM-style artifact: the filename is the
// digest, so content and name are bound and a re-write of tampered content lands
// in a different file. It refuses to overwrite an existing bundle (write-once).
// Returns the path written.
func (e *Evidence) WriteToDir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create forensics dir %q: %w", dir, err)
	}
	name := fmt.Sprintf("evidence-%s-%s.json", e.Bundle.Detection.RuleID, e.Digest[:16])
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		// Already captured (same rule + identical evidence) — WORM: do not rewrite.
		return path, nil
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal evidence: %w", err)
	}
	// O_EXCL enforces write-once at the OS level against a racing writer.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
	if err != nil {
		if os.IsExist(err) {
			return path, nil
		}
		return "", fmt.Errorf("open evidence file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return "", fmt.Errorf("write evidence: %w", err)
	}
	return path, nil
}

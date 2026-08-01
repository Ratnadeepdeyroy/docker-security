package sig

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

// --- Local transparency log -------------------------------------------------
//
// Sigstore's Rekor gives a signed, append-only record that a signature existed
// at a point in time; that record is what lets you detect a key compromise after
// the fact ("this artifact was signed by our key, but we never logged signing
// it"). A public Rekor needs network we may not have, so we implement the same
// idea locally: an append-only Merkle log whose head (a "checkpoint") is signed
// by the log's own key. An inclusion proof plus a signed checkpoint is offline,
// tamper-evident proof that an entry was recorded — verifiable without trusting
// the log operator's word, only their signature.

// LogEntry is one recorded item: the SHA-256 of the thing logged (typically a
// DSSE envelope's canonical bytes). Storing a hash, not the payload, keeps the
// log compact and avoids retaining potentially sensitive payloads.
type LogEntry struct {
	Index int    `json:"index"`
	Hash  string `json:"hash"` // hex SHA-256 of the logged bytes
}

// Checkpoint is a signed statement of the log's state at a size: the Merkle root
// over all entries [0, Size). It is the anchor a proof is checked against.
type Checkpoint struct {
	// LogID identifies the log instance (hex SHA-256 of its public key).
	LogID string `json:"log_id"`
	Size  int    `json:"size"`
	// RootHash is the hex Merkle root over the first Size entries.
	RootHash string `json:"root_hash"`
	// Signature is the log key's signature over the canonical checkpoint body.
	Signature string `json:"signature"` // base64
}

// InclusionRecord is the portable proof handed to a verifier: the entry, the
// checkpoint it was included in, and the audit path linking them.
type InclusionRecord struct {
	Entry      LogEntry   `json:"entry"`
	Checkpoint Checkpoint `json:"checkpoint"`
	// Proof is the audit path (bottom-up sibling hashes), hex-encoded.
	Proof []string `json:"proof"`
}

// TransLog is an in-memory append-only transparency log signed by a log key.
// It is safe for concurrent use.
type TransLog struct {
	mu      sync.Mutex
	signer  Signer
	logID   string
	entries [][]byte // raw logged bytes, in append order
}

// NewTransLog creates a log signed by the given key. The log ID is the key's
// content-addressed ID, so a checkpoint names exactly which log key vouches for
// it.
func NewTransLog(logKey Signer) *TransLog {
	return &TransLog{signer: logKey, logID: logKey.KeyID()}
}

// LogID returns the log's identifier.
func (l *TransLog) LogID() string { return l.logID }

// Append records bytes (typically a marshaled DSSE envelope) and returns an
// inclusion record proving membership in the resulting checkpoint. Determinism:
// the same sequence of appends yields the same roots and, since the log key is
// ed25519, the same checkpoint signatures.
func (l *TransLog) Append(data []byte) (*InclusionRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	index := len(l.entries)
	l.entries = append(l.entries, append([]byte(nil), data...))

	size := len(l.entries)
	root := merkleRoot(l.entries)
	cp, err := l.signCheckpoint(size, root)
	if err != nil {
		return nil, err
	}
	proof := inclusionProof(l.entries, index)

	sum := sha256.Sum256(data)
	rec := &InclusionRecord{
		Entry:      LogEntry{Index: index, Hash: hex.EncodeToString(sum[:])},
		Checkpoint: cp,
		Proof:      encodeProof(proof),
	}
	return rec, nil
}

// Checkpoint returns a freshly signed checkpoint over the current log state.
func (l *TransLog) Checkpoint() (Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.signCheckpoint(len(l.entries), merkleRoot(l.entries))
}

// signCheckpoint signs a checkpoint body. Caller holds the lock.
func (l *TransLog) signCheckpoint(size int, root []byte) (Checkpoint, error) {
	cp := Checkpoint{LogID: l.logID, Size: size, RootHash: hex.EncodeToString(root)}
	body := checkpointBody(cp)
	raw, err := l.signer.Sign(body)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("sign checkpoint: %w", err)
	}
	cp.Signature = base64.StdEncoding.EncodeToString(raw)
	return cp, nil
}

// checkpointBody is the canonical, signature-free byte encoding of a checkpoint,
// so signer and verifier agree on exactly what is signed.
func checkpointBody(cp Checkpoint) []byte {
	return fmt.Appendf(nil, "transparency-log-checkpoint\nlog:%s\nsize:%d\nroot:%s\n",
		cp.LogID, cp.Size, cp.RootHash)
}

// VerifyInclusion checks an inclusion record end to end against a trusted log
// verifier: (1) the checkpoint signature is valid under logVerifier, and (2) the
// entry hash + audit path recompute to the checkpoint's root. Both must hold —
// a valid proof against an unsigned root proves nothing, and a signed root with
// a bad proof does not cover this entry. The caller supplies loggedBytes (the
// original data) so the record cannot lie about what was logged.
func VerifyInclusion(rec *InclusionRecord, loggedBytes []byte, logVerifier Verifier) error {
	// (1) The checkpoint must be signed by the trusted log key.
	if rec.Checkpoint.LogID != logVerifier.KeyID() {
		return fmt.Errorf("checkpoint log id %s != trusted log %s: %w",
			short(rec.Checkpoint.LogID), short(logVerifier.KeyID()), ErrUntrusted)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(rec.Checkpoint.Signature)
	if err != nil {
		return fmt.Errorf("decode checkpoint signature: %w", ErrVerify)
	}
	if err := logVerifier.Verify(checkpointBody(rec.Checkpoint), sigBytes); err != nil {
		return fmt.Errorf("checkpoint signature: %w", err)
	}

	// (2) The logged bytes must hash to the recorded entry hash...
	sum := sha256.Sum256(loggedBytes)
	if hex.EncodeToString(sum[:]) != rec.Entry.Hash {
		return fmt.Errorf("logged bytes do not match entry hash: %w", ErrVerify)
	}
	// ...and the audit path must recompute to the signed root.
	root, err := hex.DecodeString(rec.Checkpoint.RootHash)
	if err != nil {
		return fmt.Errorf("decode checkpoint root: %w", ErrVerify)
	}
	proof, err := decodeProof(rec.Proof)
	if err != nil {
		return err
	}
	if !verifyInclusion(loggedBytes, rec.Entry.Index, rec.Checkpoint.Size, proof, root) {
		return fmt.Errorf("inclusion proof does not recompute to signed root: %w", ErrVerify)
	}
	return nil
}

// Marshal renders an inclusion record as JSON.
func (r *InclusionRecord) Marshal() ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal inclusion record: %w", err)
	}
	return data, nil
}

func encodeProof(proof [][]byte) []string {
	out := make([]string, len(proof))
	for i, p := range proof {
		out[i] = hex.EncodeToString(p)
	}
	return out
}

func decodeProof(hexes []string) ([][]byte, error) {
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("decode proof element %d: %w", i, ErrVerify)
		}
		out[i] = b
	}
	return out, nil
}

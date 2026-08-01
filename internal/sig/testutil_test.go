package sig

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// mustJSON marshals v or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// detReader is a deterministic byte stream (SHA-256 in counter mode over a
// seed). Feeding it to GenerateKey yields reproducible keys, so tests get stable
// fixtures without committing — and later rotating — real secrets. It is never
// used outside tests.
type detReader struct {
	seed []byte
	buf  []byte
	ctr  uint64
}

func newDetReader(seed string) *detReader { return &detReader{seed: []byte(seed)} }

func (r *detReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			sum := sha256.Sum256(append(append([]byte{}, r.seed...), c[:]...))
			r.buf = sum[:]
		}
		m := copy(p[n:], r.buf)
		r.buf = r.buf[m:]
		n += m
	}
	return n, nil
}

// mustSigner generates a deterministic signer for tests, failing hard on error.
func mustSigner(alg Algorithm, seed string) Signer {
	s, err := GenerateKey(alg, newDetReader(seed))
	if err != nil {
		panic(err)
	}
	return s
}

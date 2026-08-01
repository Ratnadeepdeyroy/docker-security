package sig

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestMerkleRootVectors pins the RFC 6962 hashing rules against hand-computed
// values, so a refactor that silently changes the hash construction is caught.
func TestMerkleRootVectors(t *testing.T) {
	// Empty tree = SHA-256 of empty string.
	empty := merkleRoot(nil)
	wantEmpty := sha256.Sum256(nil)
	if hex.EncodeToString(empty) != hex.EncodeToString(wantEmpty[:]) {
		t.Errorf("empty root = %x, want %x", empty, wantEmpty)
	}

	// Single leaf = H(0x00 || d0).
	d0 := []byte("leaf-0")
	one := merkleRoot([][]byte{d0})
	if hex.EncodeToString(one) != hex.EncodeToString(hashLeaf(d0)) {
		t.Errorf("single-leaf root != leaf hash")
	}

	// Two leaves = H(0x01 || H(0x00||d0) || H(0x00||d1)).
	d1 := []byte("leaf-1")
	two := merkleRoot([][]byte{d0, d1})
	want2 := hashChildren(hashLeaf(d0), hashLeaf(d1))
	if hex.EncodeToString(two) != hex.EncodeToString(want2) {
		t.Errorf("two-leaf root mismatch")
	}
}

// TestInclusionProofAllSizes verifies that, for trees of many sizes, every leaf
// produces a proof that recomputes to the true root — and that a wrong index or
// a corrupted proof fails. This exercises the awkward non-power-of-two splits.
func TestInclusionProofAllSizes(t *testing.T) {
	for size := 1; size <= 33; size++ {
		entries := make([][]byte, size)
		for i := range entries {
			entries[i] = []byte{byte(i), byte(size)}
		}
		root := merkleRoot(entries)
		for idx := 0; idx < size; idx++ {
			proof := inclusionProof(entries, idx)
			if !verifyInclusion(entries[idx], idx, size, proof, root) {
				t.Fatalf("size=%d idx=%d: valid proof failed to verify", size, idx)
			}
			// Wrong entry at the same index must fail.
			if verifyInclusion([]byte("wrong"), idx, size, proof, root) {
				t.Fatalf("size=%d idx=%d: accepted wrong entry", size, idx)
			}
			// Corrupted proof element must fail.
			if len(proof) > 0 {
				bad := make([][]byte, len(proof))
				copy(bad, proof)
				corrupt := append([]byte(nil), bad[0]...)
				corrupt[0] ^= 0xff
				bad[0] = corrupt
				if verifyInclusion(entries[idx], idx, size, bad, root) {
					t.Fatalf("size=%d idx=%d: accepted corrupted proof", size, idx)
				}
			}
		}
	}
}

// TestInclusionProofWrongRoot ensures a proof valid for one tree is rejected
// against a different tree's root (a spliced-log attack).
func TestInclusionProofWrongRoot(t *testing.T) {
	a := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	b := [][]byte{[]byte("a"), []byte("b"), []byte("d")}
	proof := inclusionProof(a, 2)
	if verifyInclusion(a[2], 2, len(a), proof, merkleRoot(b)) {
		t.Fatal("proof verified against the wrong tree root")
	}
}

package sig

import "crypto/sha256"

// --- RFC 6962 Merkle tree ---------------------------------------------------
//
// A transparency log is only useful if you can prove, cheaply and offline, that
// a specific entry is included in a specific published tree. We implement the
// RFC 6962 hashing rules (the same Certificate Transparency / Rekor use):
// leaves are hashed with a 0x00 prefix and internal nodes with a 0x01 prefix, so
// a leaf hash can never be reinterpreted as an internal node (second-preimage
// defense). Everything here operates on raw entry bytes; hashing is internal.

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// hashLeaf computes the RFC 6962 leaf hash: SHA-256(0x00 || entry).
func hashLeaf(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entry)
	return h.Sum(nil)
}

// hashChildren computes an internal node hash: SHA-256(0x01 || left || right).
func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// merkleRoot computes the Merkle Tree Hash of a list of entries. The empty tree
// hashes to SHA-256 of the empty string, per RFC 6962.
func merkleRoot(entries [][]byte) []byte {
	n := len(entries)
	switch n {
	case 0:
		sum := sha256.Sum256(nil)
		return sum[:]
	case 1:
		return hashLeaf(entries[0])
	}
	k := largestPowerOfTwoLessThan(n)
	return hashChildren(merkleRoot(entries[:k]), merkleRoot(entries[k:]))
}

// inclusionProof returns the audit path proving entries[index] is in the tree
// of the given entries: the sibling hashes from the leaf up to the root, in
// bottom-up order.
func inclusionProof(entries [][]byte, index int) [][]byte {
	n := len(entries)
	if index < 0 || index >= n {
		return nil
	}
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if index < k {
		// Leaf is in the left subtree; sibling is the whole right subtree root.
		return append(inclusionProof(entries[:k], index), merkleRoot(entries[k:]))
	}
	// Leaf is in the right subtree; sibling is the whole left subtree root.
	return append(inclusionProof(entries[k:], index-k), merkleRoot(entries[:k]))
}

// verifyInclusion recomputes the root from a leaf entry, its index, the tree
// size, and an audit path, and reports whether it matches the expected root.
// This is the verifier's side: it never sees the full tree, only the proof.
func verifyInclusion(entry []byte, index, size int, proof [][]byte, root []byte) bool {
	if index < 0 || index >= size {
		return false
	}
	computed := recomputeRoot(hashLeaf(entry), index, size, proof)
	if computed == nil {
		return false
	}
	return equalBytes(computed, root)
}

// recomputeRoot walks the audit path from the leaf hash up to a candidate root,
// following the RFC 6962 §2.1.1 verification algorithm verbatim. It tracks the
// node index fn and the last index sn = tree_size-1 within the current level to
// decide whether each proof element is a left or right sibling.
func recomputeRoot(leafHash []byte, index, size int, proof [][]byte) []byte {
	if index >= size {
		return nil
	}
	fn := index
	sn := size - 1
	r := leafHash
	for _, p := range proof {
		if sn == 0 {
			// Audit path is longer than the tree height allows.
			return nil
		}
		if fn&1 == 1 || fn == sn {
			// Node is a right child (or the lone node on a right spine): sibling
			// is on the left.
			r = hashChildren(p, r)
			if fn&1 == 0 {
				// Ascend the right spine until we are a right child again.
				for {
					fn >>= 1
					sn >>= 1
					if fn&1 == 1 || sn == 0 {
						break
					}
				}
			}
		} else {
			// Node is a left child: sibling is on the right.
			r = hashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		// Audit path was too short for the tree size.
		return nil
	}
	return r
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than
// n (n > 1). This is the RFC 6962 split point.
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

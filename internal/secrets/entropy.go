package secrets

import "math"

// --- Entropy & character-class heuristics -----------------------------------
//
// Shannon entropy is the workhorse of every generic secret detector: random
// credentials pack more bits per character than prose or identifiers. But
// entropy alone is a poor discriminator (a UUID and an API key score similarly),
// so the detectors combine an entropy floor with structural checks and — when
// enabled — the semantic classifier.

// shannonEntropy returns the Shannon entropy of s in bits per character. An
// empty string has zero entropy. Base64 tops out near 6.0, hex near 4.0.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// charClasses reports which character families appear in s. Mixed classes are a
// weak signal that a high-entropy token is a generated credential rather than a
// single-alphabet artifact (a hex digest, an all-caps constant).
func charClasses(s string) (lower, upper, digit, symbol bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	return
}

// isHex reports whether s is non-empty and made entirely of hex digits. Long
// pure-hex strings are almost always content digests (git SHAs, MD5/SHA hashes)
// rather than secrets, so detectors treat them skeptically.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isBinary reports whether data looks like a binary blob rather than text,
// using the classic "NUL byte in the first few KiB" heuristic. Binary files are
// scanned only by the strongly-anchored provider detectors, keeping the entropy
// sweep — the noisy part — to text where it belongs.
func isBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// --- Multi-entropy confidence scoring ----------------------------------------
//
// The companions to Shannon entropy below give a rounder picture of
// randomness: Rényi (α=2, collision entropy) punishes skewed distributions
// harder, and min-entropy is the pessimist's bound (guessing the most common
// symbol). Averaging them is more robust against strings engineered to fool
// any single measure. This is a *scoring* refinement only (feeds
// Detection.Confidence, see confidence.go) — every gating threshold in the
// package (minEntropy, minAssignEntropy, minBareEntropy) stays on plain
// Shannon entropy so detection behavior is unchanged.
//
// A fourth measure, Tsallis entropy (q=2), was originally blended in here
// too, scaled by a fixed ×4 to sit on roughly the same footing as the
// log-scale measures. It was removed: Tsallis(q=2) = 1 − Σp² and Rényi(α=2) =
// −log2(Σp²) are both monotone functions of the *same* underlying statistic
// (the collision probability Σp²), so the two terms moved in lockstep and
// added no independent signal — they just double-counted collision
// probability under two different names. Worse, the fixed ×4 rescale was
// calibrated against a large alphabet and, for a 16-symbol (hex) alphabet,
// made averageEntropy's own maximum achievable value (3.9375) sit below the
// "medium confidence" threshold (4.0) — mathematically unreachable for any
// hex-shaped secret, no matter how random. Dropping the redundant term fixes
// this: for a perfectly uniform k-symbol alphabet, Shannon, Rényi, and
// min-entropy all equal log2(k), so the plain 3-way average now reaches
// log2(k) exactly (4.0 for hex) at the theoretical maximum, restoring
// reachability without an arbitrary rescale.

// renyiEntropy returns the Rényi entropy of s at order α = 2, in bits. α = 2
// is also known as collision entropy, so it is not computed separately.
func renyiEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var sum float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			sum += p * p
		}
	}
	return -math.Log2(sum)
}

// minEntropyOf returns the min-entropy of s in bits: the worst case, driven
// entirely by the single most frequent symbol.
func minEntropyOf(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	max := 0
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
		if counts[s[i]] > max {
			max = counts[s[i]]
		}
	}
	return -math.Log2(float64(max) / float64(len(s)))
}

// averageEntropy blends Shannon, Rényi (α=2), and min-entropy into a single
// score. All three are already on the same log2-bits scale, so no rescaling
// is needed (see the removed-Tsallis note above for why a fourth term was
// dropped rather than patched with another rescale).
func averageEntropy(s string) float64 {
	return (shannonEntropy(s) + renyiEntropy(s) + minEntropyOf(s)) / 3
}

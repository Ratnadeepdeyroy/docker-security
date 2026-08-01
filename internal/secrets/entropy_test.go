package secrets

import "testing"

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("empty entropy = %v, want 0", e)
	}
	if e := shannonEntropy("aaaaaaaa"); e != 0 {
		t.Errorf("uniform entropy = %v, want 0", e)
	}
	// A random-looking base64 token should score well above prose.
	rand := shannonEntropy("k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi")
	prose := shannonEntropy("thequickbrownfox")
	if rand <= prose {
		t.Errorf("random entropy %.2f should exceed prose entropy %.2f", rand, prose)
	}
	if rand < 4.0 {
		t.Errorf("32-char mixed token entropy = %.2f, expected >= 4.0", rand)
	}
}

func TestCharClassesAndHex(t *testing.T) {
	l, u, d, s := charClasses("aB3!")
	if !l || !u || !d || !s {
		t.Errorf("charClasses(aB3!) = %v %v %v %v, want all true", l, u, d, s)
	}
	if !isHex("deadBEEF0123") {
		t.Error("deadBEEF0123 should be hex")
	}
	if isHex("deadbeefg") {
		t.Error("string with 'g' is not hex")
	}
}

// TestAverageEntropyHexCeilingReachesFour locks in the fix for the "medium
// confidence unreachable for hex secrets" bug: averageEntropy used to blend
// in a redundant, badly-rescaled Tsallis term that capped the maximum
// achievable score for a 16-symbol (hex) alphabet at 3.9375, below the old
// 4.0 confidence threshold. With Tsallis dropped, a perfectly uniform
// distribution over any k-symbol alphabet makes Shannon, Rényi, and
// min-entropy all equal log2(k), so their plain average reaches log2(k)
// exactly (4.0 for hex) at the theoretical ceiling — no longer capped below
// it.
func TestAverageEntropyHexCeilingReachesFour(t *testing.T) {
	// 64 hex characters with each of the 16 digits appearing exactly 4 times:
	// a perfectly uniform distribution over the hex alphabet.
	balanced := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got := averageEntropy(balanced)
	if got < 4.0 {
		t.Errorf("averageEntropy(perfectly balanced hex) = %.4f, want >= 4.0 (the hex ceiling)", got)
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("plain text config\nkey: value\n")) {
		t.Error("text should not be flagged binary")
	}
	if !isBinary([]byte("ELF\x00\x01\x02binary")) {
		t.Error("content with a NUL byte should be flagged binary")
	}
}

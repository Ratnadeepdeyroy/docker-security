package secrets

// --- AI-age feature: semantic secret classification (off by default) --------
//
// The entropy sweep's weakness is that high entropy is necessary but not
// sufficient for "this is a credential": UUIDs, content hashes, and base64
// assets all score high. Incumbent scanners either accept the resulting noise
// or drop the sweep entirely and miss context-free secrets.
//
// We instead put a Classifier between the sweep and the finding stream. It
// judges each candidate the way a reviewer would — "does this *look* like a
// generated credential, or like a hash / id / encoded blob?". The interface is
// the seam: the default HeuristicClassifier is a fast, offline, deterministic
// implementation, but a caller can drop in a local ML model without touching
// the scanner. Correctness never depends on it — with no classifier the sweep
// simply does not run.

// Candidate is a high-entropy token offered to a Classifier.
type Candidate struct {
	Value   string
	Entropy float64
}

// Verdict is a Classifier's judgment of a Candidate.
type Verdict struct {
	IsSecret   bool
	Confidence float64 // 0..1
	Label      string  // human-readable reason, e.g. "uuid", "hex-digest", "credential"
}

// Classifier decides whether a high-entropy Candidate is plausibly a secret.
// Implementations must be deterministic and side-effect free.
type Classifier interface {
	Classify(c Candidate) Verdict
}

// HeuristicClassifier is the built-in, model-free Classifier. It rejects the
// three big sources of entropy-detector noise — UUIDs, fixed-length hex digests
// (git SHAs, MD5/SHA hashes), and very long base64 asset blobs — and accepts
// mixed-alphabet tokens that look generated. It is intentionally conservative:
// when unsure it declines, because a false "secret" erodes trust faster than a
// missed context-free token (which the provider rules and assignment detector
// still have a shot at).
type HeuristicClassifier struct{}

// Classify implements Classifier.
func (HeuristicClassifier) Classify(c Candidate) Verdict {
	v := c.Value
	if isUUID(v) {
		return Verdict{IsSecret: false, Confidence: 0.95, Label: "uuid"}
	}
	// Fixed-length hex is overwhelmingly a digest, not a secret.
	if isHex(v) {
		switch len(v) {
		case 32, 40, 64, 128:
			return Verdict{IsSecret: false, Confidence: 0.9, Label: "hex-digest"}
		}
	}
	// Long, base64-ish, low-symbol-diversity strings read as encoded assets
	// (certs, images, serialized blobs) more often than credentials.
	if len(v) > 100 && looksLikeBase64Blob(v) {
		return Verdict{IsSecret: false, Confidence: 0.6, Label: "encoded-blob"}
	}
	lower, upper, digit, _ := charClasses(v)
	classes := b2i(lower) + b2i(upper) + b2i(digit)
	// A generated key mixes at least two character classes and packs real
	// entropy. Single-class tokens (all-caps constants, digit runs) are out.
	if classes >= 2 && c.Entropy >= minBareEntropy {
		return Verdict{IsSecret: true, Confidence: 0.75, Label: "credential"}
	}
	return Verdict{IsSecret: false, Confidence: 0.5, Label: "indeterminate"}
}

// isUUID reports whether v is a canonical 8-4-4-4-12 hex UUID.
func isUUID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// looksLikeBase64Blob reports whether v is dominated by base64 alphabet with the
// low per-position variety typical of encoded binary rather than a short key.
func looksLikeBase64Blob(v string) bool {
	var b64 int
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			b64++
		}
	}
	return float64(b64)/float64(len(v)) > 0.97
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

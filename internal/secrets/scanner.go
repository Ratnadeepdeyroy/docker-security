package secrets

import (
	"context"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- The scanner ------------------------------------------------------------

// defaultMaxFileBytes caps how much of any single file the scanner inspects.
// The OCI loader already bounds extraction; this is a second, tighter guard so
// a hostile 200 MiB "config" cannot dominate a scan. Secrets live in small
// text files, so this rarely bites legitimately.
const defaultMaxFileBytes = 10 << 20 // 10 MiB

// Scanner runs the detector set over content. It is safe to reuse across
// targets and is free of hidden state: two Scanners built with the same options
// produce identical results. The optional Classifier, Verifier, Baseline, and
// honeytoken set are all injected, keeping the default scan deterministic and
// offline.
type Scanner struct {
	classifier   Classifier
	verifier     Verifier
	baseline     *Baseline
	honeytokens  map[string]string // fingerprint -> label
	maxFileBytes int64
}

// Option configures a Scanner.
type Option func(*Scanner)

// New returns a Scanner with the high-signal defaults: provider rules and the
// keyword-gated assignment detector on; entropy sweep, verification, baseline,
// and honeytokens all off.
func New(opts ...Option) *Scanner {
	s := &Scanner{maxFileBytes: defaultMaxFileBytes}
	for _, o := range opts {
		o(s)
	}
	return s
}

// WithClassifier enables the context-free entropy sweep, routing each candidate
// through c. Off by default; supplying HeuristicClassifier{} is the intended
// low-cost, offline enablement.
func WithClassifier(c Classifier) Option { return func(s *Scanner) { s.classifier = c } }

// WithVerifier enables opt-in live verification of detected secrets. The
// verifier receives raw values and must never log them; the scanner discards
// them after the call. Never wire a network verifier in tests.
func WithVerifier(v Verifier) Option { return func(s *Scanner) { s.verifier = v } }

// WithBaseline suppresses detections the baseline has accepted, while still
// reporting anything new.
func WithBaseline(b *Baseline) Option { return func(s *Scanner) { s.baseline = b } }

// WithHoneytokens marks the given canary fingerprints so their appearance is
// reported as an informational canary rather than a real leak.
func WithHoneytokens(hs ...Honeytoken) Option {
	return func(s *Scanner) {
		if s.honeytokens == nil {
			s.honeytokens = map[string]string{}
		}
		for _, h := range hs {
			s.honeytokens[h.Fingerprint] = h.Label
		}
	}
}

// WithMaxFileBytes overrides the per-file scan cap (bytes).
func WithMaxFileBytes(n int64) Option { return func(s *Scanner) { s.maxFileBytes = n } }

// ScanText scans a single in-memory blob (a Dockerfile, a config file) and
// returns sorted detections. Source labels the origin for reporting.
func (s *Scanner) ScanText(ctx context.Context, path string, data []byte, src Source) []Detection {
	ds := s.scanFile(ctx, path, data, src, false, -1, "")
	SortDetections(ds)
	return ds
}

// scanFile is the core pipeline shared by every entry point. It runs the
// detectors, redacts each hit into a Detection (dropping the raw value),
// applies the baseline and honeytoken sets, and — if enabled — verifies. It
// never stores, returns, or logs a secret value.
func (s *Scanner) scanFile(ctx context.Context, path string, data []byte, src Source, deleted bool, layerIdx int, layerDigest string) []Detection {
	if int64(len(data)) > s.maxFileBytes {
		return nil // oversized: skip rather than risk a memory/time blowup
	}
	binary := isBinary(data)

	hits := applyProviderRules(data, binary)
	if !binary {
		hits = append(hits, detectAssignments(path, data)...)
		hits = append(hits, detectBareEntropy(data, s.classifier)...)
	}

	var out []Detection
	// Collapse by fingerprint so one secret is reported once per file even when
	// several detectors match it. Provider rules run before the generic ones, so
	// the more specific, higher-signal finding wins the tie.
	seen := map[string]bool{}
	// newlineOffsets is computed at most once per file, on the first hit, not
	// unconditionally: most files produce zero hits, and a file with hits pays
	// one O(len(data)) pass here instead of one O(offset) lineOf scan per hit.
	var newlines []int
	var newlinesComputed bool
	for _, h := range hits {
		if err := ctx.Err(); err != nil {
			return out
		}
		if !newlinesComputed {
			newlines = newlineOffsets(data)
			newlinesComputed = true
		}
		d := s.redact(h, path, data, newlines, src, deleted, layerIdx, layerDigest)
		if seen[d.Fingerprint] {
			continue
		}
		seen[d.Fingerprint] = true

		// A planted canary is not a leak: re-label it and never verify it.
		if label, ok := s.honeytokens[d.Fingerprint]; ok {
			applyCanary(&d, label)
			out = append(out, d)
			continue
		}
		// Baseline suppression: accepted findings drop out; new ones survive.
		if s.baseline != nil && s.baseline.Allows(d) {
			continue
		}
		if s.verifier != nil && d.verifierKey != "" {
			d.Verify = s.verify(ctx, h)
			if d.Verify == VerifyActive {
				d.Severity = engine.SeverityCritical // a confirmed-live key is the top priority
			}
		}
		out = append(out, d)
	}
	return out
}

// redact converts a rawHit into a value-free Detection. This is the only place
// the raw secret is touched: to fingerprint it and measure its entropy/length.
// newlines is data's precomputed newlineOffsets table (see scanFile), used to
// resolve h.offset to a line number in O(log lines) instead of O(offset).
func (s *Scanner) redact(h rawHit, path string, data []byte, newlines []int, src Source, deleted bool, layerIdx int, layerDigest string) Detection {
	d := Detection{
		Fingerprint: fingerprint(h.secret),
		Entropy:     shannonEntropy(h.secret),
		Length:      len(h.secret),
		Path:        path,
		Line:        lineAt(newlines, len(data), h.offset),
		Source:      src,
		Deleted:     deleted,
		LayerIndex:  layerIdx,
		LayerDigest: layerDigest,
		Verify:      VerifySkipped,
	}
	if h.generic != nil {
		g := h.generic
		d.Code, d.Slug, d.Title = g.code, g.slug, g.title
		d.Kind, d.Severity = g.kind, g.severity
		d.Remediation, d.References = g.remediation, g.references
	} else {
		r := h.rule
		d.Code, d.Slug, d.Title = r.Code, r.Slug, r.Title
		d.Kind, d.Severity = r.Kind, r.Severity
		d.Remediation, d.References = r.remediation, r.references
		d.verifierKey = r.verifierKey
	}
	if deleted {
		d.Source = SourceDeletedLayer
	}
	// Confidence is scored, never gated: it never changes whether this hit was
	// reported, only how strongly to trust it. It is computed here — the one
	// place the raw secret is available — from a bounded window of the
	// surrounding bytes, never the secret's own value.
	d.Confidence = confidenceFor(d, h.secret, contextWindow(data, h.offset))
	return d
}

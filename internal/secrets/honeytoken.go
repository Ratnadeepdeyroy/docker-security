package secrets

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- AI-age feature: honeytokens (off by default) ---------------------------
//
// A honeytoken is a decoy credential you deliberately plant in an image or repo.
// It is never valid, so any *use* of it is unambiguous evidence that someone
// pulled your artifact apart and tried the keys — a high-fidelity intrusion
// signal that almost no scanner ships (the capability spec calls it out as a
// market gap). This package provides both halves: deterministic generation of
// canaries to plant, and detection that recognizes a planted canary during a
// scan and reports it as a benign marker rather than a real leak, so a canary
// sitting where you put it never becomes a false alarm.
//
// Generation is deterministic by design: the same label always yields the same
// canary. That keeps the tool reproducible (no ambient randomness) and lets a
// planted token be re-derived and tracked without a database.

// Honeytoken is a planted decoy credential. Value is what you embed; Fingerprint
// is how the scanner recognizes it (matching the fingerprint scheme used for
// real detections, so the two share one code path).
type Honeytoken struct {
	Label       string
	Value       string
	Fingerprint string
}

// canaryBase32 encodes without padding and uppercased to match the AWS key
// alphabet (A–Z, 2–7) so a generated canary is shaped like a real AKIA key and
// therefore trips the same provider detector.
var canaryBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateHoneytoken derives a stable, AWS-access-key-shaped decoy from label.
// It performs no I/O and reads no clock or randomness, so it is safe to call in
// deterministic contexts and reproducible across machines.
func GenerateHoneytoken(label string) Honeytoken {
	sum := sha256.Sum256([]byte("dsecrat-honeytoken:" + label))
	body := canaryBase32.EncodeToString(sum[:])
	// AWS access key IDs are "AKIA" + 16 chars from [A-Z0-9]; base32 gives A–Z
	// and 2–7, a valid subset.
	value := "AKIA" + strings.ToUpper(body[:16])
	return Honeytoken{
		Label:       label,
		Value:       value,
		Fingerprint: fingerprint(value),
	}
}

// applyCanary rewrites a Detection that matched a known honeytoken into a benign
// canary marker: it is not a leak, it is your own tripwire. Severity drops to
// Info and the guidance flips from "rotate" to "alert on use".
func applyCanary(d *Detection, label string) {
	d.Code = "DS-RAT-SEC-020"
	d.Slug = "honeytoken-canary"
	d.Kind = KindCanary
	d.Severity = engine.SeverityInfo
	d.Verify = VerifySkipped
	d.verifierKey = ""
	d.Title = "Planted honeytoken (canary) detected: " + label
	d.Remediation = "This is a known decoy credential, not a real leak. Leave it in place and " +
		"alert if it is ever *used* against your provider — that use is a high-confidence intrusion signal."
	d.References = []string{"MITRE-T1552", "honeytoken"}
}

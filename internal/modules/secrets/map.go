package secrets

import (
	"fmt"
	"strconv"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/secrets"
)

// --- Detection -> Finding projection ----------------------------------------

// toFinding turns a value-free Detection into an engine Finding. The Metadata
// map is the machine-readable channel an agent consumes: type, kind,
// fingerprint, entropy, verification state, and (for images) the layer and
// whether the content was deleted. No field ever carries the secret value.
func toFinding(d secrets.Detection) engine.Finding {
	title := d.Title
	if d.Deleted {
		title += " (in a deleted/superseded layer)"
	}
	if d.Verify == secrets.VerifyActive {
		title += " — VERIFIED LIVE"
	}

	f := engine.Finding{
		RuleID:      d.Code,
		Module:      moduleName,
		Severity:    d.Severity,
		Title:       title,
		Description: describe(d),
		Resource:    resource(d),
		Location:    &engine.Location{Path: d.Path, StartLine: d.Line, EndLine: d.Line},
		Remediation: d.Remediation,
		References:  d.References,
		Metadata: map[string]string{
			"secret_type": d.Slug,
			"kind":        string(d.Kind),
			"fingerprint": d.Fingerprint,
			"entropy":     strconv.FormatFloat(d.Entropy, 'f', 2, 64),
			"confidence":  d.Confidence,
			"length":      strconv.Itoa(d.Length),
			"source":      string(d.Source),
			"verified":    string(d.Verify),
			"deleted":     strconv.FormatBool(d.Deleted),
		},
	}
	if d.LayerIndex >= 0 {
		f.Metadata["layer_index"] = strconv.Itoa(d.LayerIndex)
	}
	if d.LayerDigest != "" {
		f.Metadata["layer_digest"] = d.LayerDigest
	}
	return f
}

// describe renders a human, value-free one-liner. It states what was found and
// how strong the signal is, so a reviewer can triage without seeing the secret.
func describe(d secrets.Detection) string {
	base := fmt.Sprintf("A %s secret (%s) was detected at %s [fingerprint %s, %d bytes, entropy %.2f, confidence: %s].",
		d.Kind, d.Slug, location(d), d.Fingerprint, d.Length, d.Entropy, d.Confidence)
	switch d.Verify {
	case secrets.VerifyActive:
		base += " Live-verification confirmed this credential is ACTIVE — rotate it now."
	case secrets.VerifyInactive:
		base += " Live-verification reports this credential is inactive (likely already rotated)."
	}
	if d.Deleted {
		base += " It survives in a superseded layer and is still extractable from the image."
	}
	return base
}

// resource is the short subject shown in table output.
func resource(d secrets.Detection) string {
	if d.LayerDigest != "" {
		return fmt.Sprintf("%s@%s", d.Path, d.LayerDigest)
	}
	return d.Path
}

// location is a human "path:line" for the description.
func location(d secrets.Detection) string {
	if d.Line > 0 {
		return fmt.Sprintf("%s:%d", d.Path, d.Line)
	}
	return d.Path
}

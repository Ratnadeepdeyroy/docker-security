package verify

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Ratnadeepdeyroy/docker-security/internal/attest"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// --- Rule IDs ---------------------------------------------------------------
//
// All findings from this phase use the DS-RAT-SUP- namespace. Positive (INFO)
// findings are emitted too, so a passing image produces evidence, not silence.

const (
	ruleNotConfigured   = "DS-RAT-SUP-010"
	ruleUnsigned        = "DS-RAT-SUP-001"
	ruleSigInvalid      = "DS-RAT-SUP-002"
	rulePolicyViolation = "DS-RAT-SUP-003"
	ruleDigestMismatch  = "DS-RAT-SUP-004"
	ruleAttestMissing   = "DS-RAT-SUP-005"
	ruleTlogMissing     = "DS-RAT-SUP-006"
	ruleSigVerified     = "DS-RAT-SUP-100"
	ruleAttestVerified  = "DS-RAT-SUP-101"
	ruleAgentAction     = "DS-RAT-SUP-030"
	ruleVerdict         = "DS-RAT-SUP-200"
)

const moduleName = "verify"

// verdict accumulates the outcome of verifying one image, both as findings and
// as the machine-readable levels that feed a VSA.
type verdict struct {
	findings       []engine.Finding
	verifiedLevels []string
	failed         bool
}

func (v *verdict) add(f engine.Finding) {
	if f.Severity >= engine.SeverityHigh {
		v.failed = true
	}
	v.findings = append(v.findings, f)
}

func (v *verdict) level(l string) { v.verifiedLevels = append(v.verifiedLevels, l) }

// verifyBundle runs the full verification of a bundle against resolved trust and
// returns findings plus a pass/fail verdict. imageDigest is the digest actually
// under test (from the image on disk / the registry); it is cross-checked
// against the bundle's subject and every signed payload, which is what stops a
// valid bundle for image A from authenticating image B.
func verifyBundle(res *resolved, bundle *sig.Bundle, imageDigest, resource string) *verdict {
	v := &verdict{}

	// A configured-but-empty trust root can verify nothing; say so plainly rather
	// than emit misleading "unsigned" findings.
	if res.trust.Len() == 0 {
		v.add(finding(ruleNotConfigured, engine.SeverityInfo,
			"Supply-chain verification not configured",
			"No trusted signing keys are configured, so image signatures and attestations cannot be verified. Provide a trust config to enable enforcement.",
			resource, "Configure a trust root (trusted public keys + signer policy) for this target."))
		return v
	}

	// The bundle must be about the image under test.
	if imageDigest != "" && bundle.SubjectDigest != imageDigest {
		v.add(finding(ruleDigestMismatch, engine.SeverityCritical,
			"Signature bundle targets a different image digest",
			fmt.Sprintf("Bundle subject digest %s does not match the image under verification (%s). This is a sign of a replayed or swapped signature.", bundle.SubjectDigest, imageDigest),
			resource, "Reject this image: obtain signatures produced for this exact digest."))
		// Keep going so we still report signature validity, but the verdict fails.
	}

	// The digest we bind checks to: prefer the actual image digest, else trust the
	// bundle's own subject (still cross-checked against signed payloads below).
	subject := imageDigest
	if subject == "" {
		subject = bundle.SubjectDigest
	}

	sigCount := verifySignatures(v, res, bundle, subject, resource)
	if sigCount == 0 {
		v.add(finding(ruleUnsigned, engine.SeverityHigh,
			"Image is not signed",
			"No verifiable signature was found for this image. Unsigned images have no provenance guarantee.",
			resource, "Sign the image by digest with a trusted key (dsecrat sign)."))
	} else {
		v.level("SIGNED")
	}

	verifyAttestations(v, res, bundle, subject, resource)

	return v
}

// verifySignatures verifies every signature entry and returns how many verified.
func verifySignatures(v *verdict, res *resolved, bundle *sig.Bundle, subject, resource string) int {
	verified := 0
	for _, e := range bundle.Entries {
		if e.Kind != sig.KindSignature || e.Envelope == nil {
			continue
		}
		if e.Envelope.PayloadType != sig.SimpleSigningMediaType {
			continue
		}
		signer, err := res.trust.Verify(e.Envelope, res.policy)
		if err != nil {
			v.add(signatureError(err, resource))
			continue
		}
		// The signature must bind to the subject digest (anti-replay).
		payload, err := e.Envelope.DecodePayload()
		if err != nil {
			v.add(finding(ruleSigInvalid, engine.SeverityHigh, "Signature payload unreadable", err.Error(), resource, "Re-sign the image."))
			continue
		}
		ss, err := sig.ParseImagePayload(payload)
		if err != nil {
			v.add(finding(ruleSigInvalid, engine.SeverityHigh, "Signature payload malformed", err.Error(), resource, "Re-sign the image."))
			continue
		}
		if ss.SignedDigest() != subject {
			v.add(finding(ruleDigestMismatch, engine.SeverityCritical,
				"Signature binds to a different digest",
				fmt.Sprintf("Signature payload commits to %s, not the image under test (%s).", ss.SignedDigest(), subject),
				resource, "Reject this image; the signature does not cover its content."))
			continue
		}
		// Transparency-log inclusion, when required or present.
		if !checkInclusion(v, res, e, resource) {
			continue
		}
		verified++
		v.add(findingWithMeta(ruleSigVerified, engine.SeverityInfo,
			"Image signature verified",
			fmt.Sprintf("Signed by trusted key %s (identity %q).", shortID(signer.KeyID), signer.Identity),
			resource, "", map[string]string{
				"keyid":    signer.KeyID,
				"identity": signer.Identity,
				"digest":   subject,
			}))
	}
	return verified
}

// checkInclusion verifies a transparency-log proof if present or required. It
// returns false only when a required proof is missing/invalid (which the caller
// treats as failing that signature).
func checkInclusion(v *verdict, res *resolved, e sig.BundleEntry, resource string) bool {
	if e.Inclusion == nil {
		if res.cfg.RequireTransparencyLog {
			v.add(finding(ruleTlogMissing, engine.SeverityMedium,
				"Signature lacks a transparency-log proof",
				"Policy requires a transparency-log inclusion proof, but this signature carries none.",
				resource, "Record signatures in the transparency log (dsecrat sign --tlog)."))
			return false
		}
		return true
	}
	if res.logVer == nil {
		// A proof is present but we have no log key to trust it; note it but do
		// not fail the signature on that basis alone.
		v.add(finding(ruleTlogMissing, engine.SeverityInfo,
			"Transparency-log proof present but no log key configured",
			"An inclusion proof is attached but no transparency-log public key is configured to verify it.",
			resource, "Configure log_public_key_pem to verify inclusion proofs."))
		return true
	}
	envBytes, _ := e.Envelope.Marshal()
	if err := sig.VerifyInclusion(e.Inclusion, envBytes, res.logVer); err != nil {
		v.add(finding(ruleTlogMissing, engine.SeverityHigh,
			"Transparency-log inclusion proof failed",
			err.Error(), resource, "The signing record cannot be verified; investigate the log."))
		return !res.cfg.RequireTransparencyLog
	}
	v.level("TRANSPARENCY_LOG")
	return true
}

// verifyAttestations verifies attestation entries, tracks which predicate types
// verified, and flags any required predicate that is absent.
func verifyAttestations(v *verdict, res *resolved, bundle *sig.Bundle, subject, resource string) {
	seen := map[string]bool{}
	for _, e := range bundle.Entries {
		if e.Kind != sig.KindAttestation || e.Envelope == nil {
			continue
		}
		result, err := attest.Verify(e.Envelope, res.trust, attest.Requirement{
			ExpectedDigest: subject,
			Policy:         res.policy,
		})
		if err != nil {
			v.add(attestationError(err, resource))
			continue
		}
		pt := result.Statement.PredicateType
		seen[pt] = true

		// AI-age agent-action attestations are only surfaced when enabled.
		if pt == attest.PredicateAgentAction {
			if !res.cfg.EnableAgentActions {
				continue
			}
			v.level("AGENT_ATTESTED")
			v.add(agentActionFinding(result, resource))
			continue
		}

		v.level(predicateLevel(pt))
		v.add(findingWithMeta(ruleAttestVerified, engine.SeverityInfo,
			"Attestation verified",
			fmt.Sprintf("%s attestation signed by %q.", predicateLabel(pt), result.Signer.Identity),
			resource, "", map[string]string{
				"predicate_type": pt,
				"identity":       result.Signer.Identity,
			}))
	}

	// Enforce required attestations.
	for _, want := range res.cfg.RequireAttestations {
		if !seen[want] {
			v.add(finding(ruleAttestMissing, engine.SeverityHigh,
				"Required attestation missing",
				fmt.Sprintf("Policy requires a %s attestation, but none was found or verified.", predicateLabel(want)),
				resource, "Attach and sign the required attestation (dsecrat attest)."))
		}
	}
}

// signatureError maps a trust-root error onto the right rule/severity.
func signatureError(err error, resource string) engine.Finding {
	switch {
	case errors.Is(err, sig.ErrPolicy):
		return finding(rulePolicyViolation, engine.SeverityHigh,
			"Signature signer not allowed by policy",
			err.Error(), resource, "Sign with an identity on the policy allow-list.")
	case errors.Is(err, sig.ErrUntrusted):
		return finding(ruleSigInvalid, engine.SeverityCritical,
			"Signature not made by a trusted key",
			err.Error(), resource, "Reject the image or add the signer to the trust root if legitimate.")
	default:
		return finding(ruleSigInvalid, engine.SeverityCritical,
			"Signature verification failed", err.Error(), resource, "Reject the image.")
	}
}

func attestationError(err error, resource string) engine.Finding {
	switch {
	case errors.Is(err, sig.ErrPolicy):
		return finding(rulePolicyViolation, engine.SeverityHigh,
			"Attestation signer not allowed by policy", err.Error(), resource, "Sign attestations with an allowed identity.")
	case errors.Is(err, sig.ErrUntrusted):
		return finding(ruleSigInvalid, engine.SeverityHigh,
			"Attestation not made by a trusted key", err.Error(), resource, "Reject or add the signer if legitimate.")
	default:
		return finding(ruleSigInvalid, engine.SeverityHigh,
			"Attestation verification failed", err.Error(), resource, "Investigate the attestation.")
	}
}

func agentActionFinding(result *attest.Result, resource string) engine.Finding {
	var action attest.AgentAction
	_ = result.Statement.DecodePredicate(&action)
	return findingWithMeta(ruleAgentAction, engine.SeverityInfo,
		"AI-agent action attestation verified",
		fmt.Sprintf("Agent %q (model %q) performed %q via %q; prompt sha256 %s.",
			action.Agent.ID, action.Agent.Model, action.Action.Type, action.Action.Tool, shortID(action.Prompt.SHA256)),
		resource, "", map[string]string{
			"agent_id":    action.Agent.ID,
			"agent_model": action.Agent.Model,
			"action_type": action.Action.Type,
			"prompt_hash": action.Prompt.SHA256,
			"identity":    result.Signer.Identity,
		})
}

// --- Finding helpers --------------------------------------------------------

func finding(rule string, sev engine.Severity, title, desc, resource, remediation string) engine.Finding {
	return findingWithMeta(rule, sev, title, desc, resource, remediation, nil)
}

func findingWithMeta(rule string, sev engine.Severity, title, desc, resource, remediation string, meta map[string]string) engine.Finding {
	f := engine.Finding{
		RuleID:      rule,
		Module:      moduleName,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Resource:    resource,
		Remediation: remediation,
		References: []string{
			"https://slsa.dev/spec/v1.0/",
			"https://github.com/secure-systems-lab/dsse",
		},
		Metadata: meta,
	}
	return f
}

func predicateLabel(pt string) string {
	switch pt {
	case attest.PredicateSLSAProvenance:
		return "SLSA provenance"
	case attest.PredicateCycloneDX, attest.PredicateSPDX:
		return "SBOM"
	case attest.PredicateOpenVEX:
		return "VEX"
	case attest.PredicateAgentAction:
		return "agent-action"
	case attest.PredicateVSA:
		return "verification-summary"
	default:
		return pt
	}
}

func predicateLevel(pt string) string {
	switch pt {
	case attest.PredicateSLSAProvenance:
		return "SLSA_PROVENANCE"
	case attest.PredicateCycloneDX, attest.PredicateSPDX:
		return "SBOM_PRESENT"
	case attest.PredicateOpenVEX:
		return "VEX_PRESENT"
	default:
		return "ATTESTED"
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// sortedLevels returns the verified levels de-duplicated and sorted, for stable
// output in the verdict finding and any emitted VSA.
func sortedLevels(levels []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range levels {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

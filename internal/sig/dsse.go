package sig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

// --- DSSE: Dead Simple Signing Envelope ------------------------------------
//
// A signature over a bare payload is ambiguous: the same bytes may be a valid
// SBOM, a provenance statement, or a signature payload, and an attacker who can
// make a verifier accept one type as another gets a type-confusion primitive.
// DSSE closes that by signing PAE(payloadType, payload) — the type is inside the
// signed message. We implement DSSE v1 exactly (github.com/secure-systems-lab/
// dsse), so envelopes we emit interoperate with the wider ecosystem's tooling.

// Envelope is a DSSE v1 envelope. The payload is transported base64-encoded; the
// signatures cover the PAE of (payloadType, raw payload), never the base64 text.
type Envelope struct {
	// Payload is the base64 (standard, padded) encoding of the raw payload.
	Payload string `json:"payload"`
	// PayloadType is the payload's type URI (e.g. an in-toto or simple-signing
	// media type). It is authenticated: it is part of the signed PAE.
	PayloadType string `json:"payloadType"`
	// Signatures holds one entry per signer.
	Signatures []Signature `json:"signatures"`
}

// Signature is one signer's contribution to an Envelope.
type Signature struct {
	// KeyID identifies the signing key (content-addressed; see KeyID).
	KeyID string `json:"keyid,omitempty"`
	// Sig is the base64 (standard, padded) signature over the PAE.
	Sig string `json:"sig"`
}

// pae computes the DSSE Pre-Authentication Encoding:
//
//	"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//
// with SP a single 0x20 space and LEN the ASCII-decimal byte length. Encoding
// the lengths makes the boundary between type and body unforgeable, so no
// crafted payload can shift bytes across the type/body boundary.
func pae(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// PAE exposes the pre-authentication encoding for callers that need to sign or
// verify the exact bytes a DSSE signature covers (e.g. a transparency log entry).
func PAE(payloadType string, payload []byte) []byte { return pae(payloadType, payload) }

// SignEnvelope builds a DSSE envelope over payload with the given type, signed
// by each signer. Multiple signers produce multiple signatures on one envelope
// (threshold/co-signing), which is how "N of M maintainers" policies are met.
func SignEnvelope(payloadType string, payload []byte, signers ...Signer) (*Envelope, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("SignEnvelope: no signers provided")
	}
	msg := pae(payloadType, payload)
	env := &Envelope{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: payloadType,
	}
	for _, s := range signers {
		raw, err := s.Sign(msg)
		if err != nil {
			return nil, fmt.Errorf("sign with %s: %w", short(s.KeyID()), err)
		}
		env.Signatures = append(env.Signatures, Signature{
			KeyID: s.KeyID(),
			Sig:   base64.StdEncoding.EncodeToString(raw),
		})
	}
	return env, nil
}

// DecodePayload returns the raw (base64-decoded) payload bytes.
func (e *Envelope) DecodePayload() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}
	return raw, nil
}

// VerifyWith checks the envelope against a single verifier and returns nil only
// if at least one signature on the envelope validates under that key. It does
// not consult a trust root or policy — callers that need "who is allowed to
// sign" use TrustRoot.Verify instead.
func (e *Envelope) VerifyWith(v Verifier) error {
	payload, err := e.DecodePayload()
	if err != nil {
		return err
	}
	msg := pae(e.PayloadType, payload)
	for _, s := range e.Signatures {
		// If the signature carries a key ID, it must match — a mismatched ID is a
		// sign the envelope was assembled for a different key and we refuse to
		// "try anyway", which would let an attacker probe keys.
		if s.KeyID != "" && s.KeyID != v.KeyID() {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if err := v.Verify(msg, raw); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no signature verified under key %s: %w", short(v.KeyID()), ErrVerify)
}

// MarshalJSON / round-tripping uses the standard library directly; Envelope is a
// plain struct. A helper keeps call sites tidy and consistent.

// Marshal serializes the envelope as canonical, compact JSON.
func (e *Envelope) Marshal() ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("marshal DSSE envelope: %w", err)
	}
	return data, nil
}

// ParseEnvelope decodes a DSSE envelope from JSON, rejecting obviously malformed
// input (missing payload type or signatures) so downstream code can assume a
// well-formed shape.
func ParseEnvelope(data []byte) (*Envelope, error) {
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		// Fall back to lenient decoding: envelopes from other tools may carry
		// extra fields we don't model. We still validate the required ones below.
		if err2 := json.Unmarshal(data, &e); err2 != nil {
			return nil, fmt.Errorf("parse DSSE envelope: %w", err)
		}
	}
	if e.PayloadType == "" {
		return nil, fmt.Errorf("parse DSSE envelope: missing payloadType")
	}
	if len(e.Signatures) == 0 {
		return nil, fmt.Errorf("parse DSSE envelope: no signatures")
	}
	if _, err := e.DecodePayload(); err != nil {
		return nil, err
	}
	return &e, nil
}

// Package policy is a deterministic, dependency-free policy-as-code engine for
// docker-security. It compiles a versioned policy document (rules written in a
// small boolean expression language) and evaluates it against a unified Input —
// scan findings, image identity, workload security context, and supply-chain
// attestation state — to produce an allow / warn / deny Decision.
//
// The engine is the shared core behind two enforcement points: a CI gate (the
// internal/modules/policy Module, shift-left over scan results) and a Kubernetes
// ValidatingWebhook (internal/admission). Both call the same Evaluate, so a rule
// behaves identically in a pipeline and at admission time.
//
// Two properties are load-bearing. First, evaluation is pure: it reads only its
// Input and an injected clock (for waiver expiry), never the wall clock or a
// random source, so the same inputs always yield the same Decision — that is what
// makes policy testable as code. Second, it fails closed: a malformed policy or
// an evaluation error is never silently treated as "allow"; callers surface it
// and, in admission, deny.
package policy

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// --- Evaluation input ------------------------------------------------------

// Input is the immutable world a policy sees. It is assembled by a caller (the
// CI gate builds it from a scan Report; the admission webhook builds it from an
// AdmissionReview) and then evaluated without further I/O.
type Input struct {
	// Findings are the security findings under judgement (from a scan Report).
	Findings []engine.Finding
	// Image identifies the artifact being gated.
	Image Image
	// Workload is the Kubernetes security context, when gating a manifest.
	Workload Workload
	// Attest is the supply-chain verification state. It is an interface so the
	// policy engine never imports the attestation package — Phase 2 supplies an
	// adapter; tests and the CI gate use StaticAttestation.
	Attest AttestationState
	// Licenses lists SPDX license identifiers discovered in the artifact's SBOM.
	Licenses []string
	// Packages lists package names discovered in the artifact's SBOM.
	Packages []string
}

// Image is the identity of the artifact under policy.
type Image struct {
	Reference  string `json:"reference,omitempty"`
	Registry   string `json:"registry,omitempty"`
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

// Workload is the security-relevant projection of a Kubernetes pod spec, flat
// enough for a policy rule to reference directly (privileged, runs_as_root, …).
type Workload struct {
	Present                  bool     `json:"present,omitempty"`
	Privileged               bool     `json:"privileged,omitempty"`
	RunAsRoot                bool     `json:"run_as_root,omitempty"`
	HostNetwork              bool     `json:"host_network,omitempty"`
	HostPID                  bool     `json:"host_pid,omitempty"`
	HostIPC                  bool     `json:"host_ipc,omitempty"`
	ReadOnlyRootFS           bool     `json:"read_only_root_fs,omitempty"`
	AllowPrivilegeEscalation bool     `json:"allow_privilege_escalation,omitempty"`
	UsesHostPath             bool     `json:"uses_host_path,omitempty"`
	Capabilities             []string `json:"capabilities,omitempty"`
	Images                   []string `json:"images,omitempty"`
}

// --- Attestation state (decoupled from Phase 2) ----------------------------

// AttestationState is the minimal supply-chain view the policy engine needs. It
// is deliberately tiny so the verify/attest packages can satisfy it with a thin
// adapter (a master action) without the policy engine depending on them, keeping
// the two phases decoupled and independently testable.
type AttestationState interface {
	// Signed reports whether the artifact carries a verified signature.
	Signed() bool
	// Verified reports whether an attestation of the given predicate-type URI
	// was present and verified.
	Verified(predicateType string) bool
	// VerifiedPredicates lists all verified predicate-type URIs.
	VerifiedPredicates() []string
}

// StaticAttestation is a plain-data AttestationState. The CI gate builds one
// from a scan Report's verification verdict; tests construct it directly. A nil
// AttestationState is treated as "nothing verified" (the fail-closed default).
type StaticAttestation struct {
	IsSigned   bool     `json:"signed,omitempty"`
	Predicates []string `json:"predicates,omitempty"`
}

func (s StaticAttestation) Signed() bool { return s.IsSigned }

func (s StaticAttestation) Verified(predicateType string) bool {
	for _, p := range s.Predicates {
		if p == predicateType {
			return true
		}
	}
	return false
}

func (s StaticAttestation) VerifiedPredicates() []string { return s.Predicates }

// attestOf returns the input's attestation state, substituting an empty state
// when none was supplied so builtins never dereference a nil interface.
func (in *Input) attestOf() AttestationState {
	if in.Attest == nil {
		return StaticAttestation{}
	}
	return in.Attest
}

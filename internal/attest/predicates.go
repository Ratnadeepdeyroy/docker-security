package attest

import "time"

// --- Predicate schemas ------------------------------------------------------
//
// These mirror the public predicate schemas closely enough to interoperate,
// while staying small: we model the fields a verifier or an operator actually
// reasons about, not every optional field. All timestamps are caller-supplied
// (never sampled from the clock in library code) so attestations are
// reproducible in tests.

// SLSAProvenance is a trimmed SLSA v1 provenance predicate: who built the
// artifact, from what, and how. It answers "did this come from our pipeline?".
type SLSAProvenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes the build's inputs.
type BuildDefinition struct {
	// BuildType is a URI naming the build process convention.
	BuildType string `json:"buildType"`
	// ExternalParameters are the top-level, externally supplied inputs (e.g. the
	// source repo and ref).
	ExternalParameters map[string]string `json:"externalParameters,omitempty"`
	// ResolvedDependencies pins the materials the build consumed.
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// RunDetails describes the builder and this specific run.
type RunDetails struct {
	Builder    Builder    `json:"builder"`
	Metadata   BuildMeta  `json:"metadata,omitempty"`
	Byproducts []struct{} `json:"byproducts,omitempty"`
}

// Builder identifies the build platform. Its ID is the value provenance policy
// keys on ("was this built by our trusted builder?").
type Builder struct {
	ID string `json:"id"`
}

// BuildMeta carries per-invocation metadata.
type BuildMeta struct {
	InvocationID string     `json:"invocationId,omitempty"`
	StartedOn    *time.Time `json:"startedOn,omitempty"`
	FinishedOn   *time.Time `json:"finishedOn,omitempty"`
}

// ResourceDescriptor names a material/dependency with its digest.
type ResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// --- OpenVEX ---------------------------------------------------------------

// VEXStatus is an OpenVEX status label.
type VEXStatus string

const (
	VEXNotAffected        VEXStatus = "not_affected"
	VEXAffected           VEXStatus = "affected"
	VEXFixed              VEXStatus = "fixed"
	VEXUnderInvestigation VEXStatus = "under_investigation"
)

// OpenVEX is a minimal OpenVEX document: a set of statements about how specific
// products relate to specific vulnerabilities. It lets a verifier honor a
// vendor's "not affected" assertion instead of failing on a raw CVE match.
type OpenVEX struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  time.Time      `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []VEXStatement `json:"statements"`
}

// VEXStatement is one product/vuln/status assertion.
type VEXStatement struct {
	Vulnerability VEXVuln   `json:"vulnerability"`
	Products      []string  `json:"products"`
	Status        VEXStatus `json:"status"`
	// Justification explains a not_affected status (e.g.
	// "vulnerable_code_not_in_execute_path").
	Justification string `json:"justification,omitempty"`
}

// VEXVuln names a vulnerability.
type VEXVuln struct {
	Name string `json:"name"` // e.g. "CVE-2024-0001"
}

// --- SLSA Verification Summary Attestation (VSA) ----------------------------

// VerdictResult is the pass/fail outcome recorded in a VSA.
type VerdictResult string

const (
	VerdictPassed VerdictResult = "PASSED"
	VerdictFailed VerdictResult = "FAILED"
)

// VSA is a Verification Summary Attestation: a single, signed "we checked this
// and here is the verdict" that a downstream (deploy) system — or an
// orchestration agent — can trust without re-running every underlying check.
type VSA struct {
	Verifier           VSAVerifier   `json:"verifier"`
	TimeVerified       time.Time     `json:"timeVerified"`
	ResourceURI        string        `json:"resourceUri"`
	Policy             VSAPolicy     `json:"policy"`
	VerificationResult VerdictResult `json:"verificationResult"`
	// VerifiedLevels lists the properties that passed (e.g. "SIGNED",
	// "SLSA_PROVENANCE", "SBOM_PRESENT").
	VerifiedLevels []string `json:"verifiedLevels"`
}

// VSAVerifier identifies who performed the verification.
type VSAVerifier struct {
	ID string `json:"id"`
}

// VSAPolicy names the policy the verdict was computed under.
type VSAPolicy struct {
	URI string `json:"uri,omitempty"`
}

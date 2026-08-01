package admission

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

// --- Image context resolution (decoupled from Phase 1/2) -------------------

// ImageResolver supplies the per-image context a policy may reference —
// signature/attestation state, scan findings, and licenses. It is an interface
// so the webhook can run with nothing (the default resolves to "unsigned, no
// findings", which makes signature rules fail closed) or be wired to the verify
// and vuln phases later without this package importing them (a master action).
type ImageResolver interface {
	Resolve(imageRef string) (policy.AttestationState, []engine.Finding, []string)
}

// emptyResolver is the fail-closed default: it vouches for nothing.
type emptyResolver struct{}

func (emptyResolver) Resolve(string) (policy.AttestationState, []engine.Finding, []string) {
	return policy.StaticAttestation{}, nil, nil
}

// --- Reviewer --------------------------------------------------------------

// Reviewer evaluates AdmissionReviews against a compiled policy.
type Reviewer struct {
	engine   *policy.Engine
	resolver ImageResolver
	now      func() time.Time
	explain  bool
	failOpen bool
}

// Option configures a Reviewer.
type Option func(*Reviewer)

// WithResolver sets the image-context resolver.
func WithResolver(r ImageResolver) Option { return func(rv *Reviewer) { rv.resolver = r } }

// WithClock injects the time source (tests pin it; production uses time.Now).
func WithClock(now func() time.Time) Option { return func(rv *Reviewer) { rv.now = now } }

// WithExplain turns on agent-consumable explanations in responses. Off by
// default: the deterministic allow/deny never depends on it.
func WithExplain(on bool) Option { return func(rv *Reviewer) { rv.explain = on } }

// WithFailOpen makes internal evaluation errors allow instead of deny. The
// default is fail-closed; fail-open is an explicit, logged operator choice for
// audit rollouts.
func WithFailOpen(on bool) Option { return func(rv *Reviewer) { rv.failOpen = on } }

// NewReviewer builds a Reviewer over a compiled policy engine.
func NewReviewer(eng *policy.Engine, opts ...Option) *Reviewer {
	rv := &Reviewer{engine: eng, resolver: emptyResolver{}, now: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(rv)
	}
	return rv
}

// Review evaluates one AdmissionReview and returns the response review. It never
// returns an error: every failure path resolves to an allow/deny per the
// fail-open/closed setting, because the API server needs a verdict, not a stack
// trace.
func (rv *Reviewer) Review(ar *AdmissionReview) *AdmissionReview {
	if ar == nil || ar.Request == nil {
		return newResponseReview(rv.onError("", "missing admission request"))
	}
	req := ar.Request

	info, err := extractWorkload(req.Object)
	if err != nil {
		return newResponseReview(rv.onError(req.UID, "could not parse workload: "+err.Error()))
	}

	dec := rv.decide(info, rv.now())
	return newResponseReview(rv.toResponse(req.UID, dec))
}

// decision is the admission-level aggregate over every image in the workload.
type decision struct {
	blocked  bool
	verdict  policy.DecisionType
	denials  []imageRule
	warnings []imageRule
	ex       *policy.Explanation
	evalErr  bool
}

// imageRule pairs a fired rule with the image it fired for (workload-level rules
// carry an empty image).
type imageRule struct {
	image string
	rule  policy.RuleResult
}

// decide evaluates the policy once per container image (sharing the flattened
// workload) and aggregates: the workload is denied if any image is denied. A
// workload with no images is still evaluated once so workload-level rules apply.
func (rv *Reviewer) decide(info workloadInfo, now time.Time) decision {
	images := info.images
	if len(images) == 0 {
		images = []string{""}
	}

	var dec decision
	dec.verdict = policy.DecisionAllow
	seenDeny := map[string]bool{}
	seenWarn := map[string]bool{}

	for _, imgRef := range images {
		att, findings, licenses := rv.resolver.Resolve(imgRef)
		in := &policy.Input{
			Workload: info.workload,
			Image:    parseImageRef(imgRef),
			Attest:   att,
			Findings: findings,
			Licenses: licenses,
		}
		res := rv.engine.Evaluate(in, now)

		switch res.Decision {
		case policy.DecisionDeny:
			dec.verdict = policy.DecisionDeny
		case policy.DecisionWarn:
			if dec.verdict != policy.DecisionDeny {
				dec.verdict = policy.DecisionWarn
			}
		}
		for _, d := range res.Denials() {
			if key := imgRef + "|" + d.RuleID; !seenDeny[key] {
				seenDeny[key] = true
				dec.denials = append(dec.denials, imageRule{image: imgRef, rule: d})
			}
			if d.Error != "" {
				dec.evalErr = true
			}
		}
		for _, wn := range res.Warnings() {
			if key := imgRef + "|" + wn.RuleID; !seenWarn[key] {
				seenWarn[key] = true
				dec.warnings = append(dec.warnings, imageRule{image: imgRef, rule: wn})
			}
		}
		if rv.explain {
			dec.ex = mergeExplanation(dec.ex, rv.engine.Explain(res, in), imgRef)
		}
	}

	dec.blocked = dec.verdict == policy.DecisionDeny
	return dec
}

// toResponse renders an aggregate decision into an AdmissionResponse.
func (rv *Reviewer) toResponse(uid string, dec decision) *AdmissionResponse {
	// Fail-open only rescues internal evaluation errors, never a clean deny: an
	// operator opting into audit mode must not thereby admit a policy-violating
	// workload that evaluated correctly.
	if dec.blocked && dec.evalErr && rv.failOpen {
		resp := &AdmissionResponse{UID: uid, Allowed: true}
		resp.Warnings = append(warningLines(dec.warnings), "policy evaluation error (fail-open): admitted for audit")
		rv.attachAudit(resp, dec)
		return resp
	}

	resp := &AdmissionResponse{UID: uid, Allowed: !dec.blocked}
	resp.Warnings = warningLines(dec.warnings)

	if dec.blocked {
		resp.Status = &Status{
			Code:    403,
			Reason:  "Forbidden",
			Message: denyMessage(dec.denials),
		}
	}
	rv.attachAudit(resp, dec)
	return resp
}

// attachAudit records the machine-readable decision (and, when enabled, the full
// explanation) as audit annotations for an agent or the audit log to consume.
func (rv *Reviewer) attachAudit(resp *AdmissionResponse, dec decision) {
	ann := map[string]string{"docker-security.policy/decision": string(dec.verdict)}
	if rv.explain && dec.ex != nil {
		if data, err := json.Marshal(dec.ex); err == nil {
			ann["docker-security.policy/explanation"] = string(data)
		}
	}
	resp.AuditAnnotations = ann
}

// onError builds the fail-closed (or fail-open) response for an input we could
// not even evaluate — a malformed object or a missing request.
func (rv *Reviewer) onError(uid, msg string) *AdmissionResponse {
	if rv.failOpen {
		return &AdmissionResponse{UID: uid, Allowed: true, Warnings: []string{"admission: " + msg + " (fail-open)"}}
	}
	return &AdmissionResponse{
		UID:     uid,
		Allowed: false,
		Status:  &Status{Code: 400, Reason: "Forbidden", Message: "admission: " + msg + " (fail-closed)"},
	}
}

// denyMessage composes the human deny reason shown to whoever ran kubectl.
func denyMessage(denials []imageRule) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("denied by docker-security policy (%d violation(s)):", len(denials)))
	for _, d := range denials {
		reason := d.rule.Message
		if d.rule.Error != "" {
			reason = "evaluation error (fail-closed): " + d.rule.Error
		}
		if d.image != "" {
			b.WriteString(fmt.Sprintf("\n  - [%s] %s: %s", d.rule.RuleID, d.image, reason))
		} else {
			b.WriteString(fmt.Sprintf("\n  - %s: %s", d.rule.RuleID, reason))
		}
		if d.rule.Remediation != "" {
			b.WriteString("\n    fix: " + d.rule.Remediation)
		}
	}
	return b.String()
}

// warningLines renders warn-level firings as advisory strings (K8s shows these
// to the user without blocking).
func warningLines(warnings []imageRule) []string {
	var out []string
	for _, w := range warnings {
		msg := w.rule.Message
		if w.image != "" {
			out = append(out, fmt.Sprintf("[%s] %s: %s", w.rule.RuleID, w.image, msg))
		} else {
			out = append(out, fmt.Sprintf("%s: %s", w.rule.RuleID, msg))
		}
	}
	sort.Strings(out)
	return out
}

// mergeExplanation folds a per-image explanation into the aggregate, prefixing
// each rule reason with its image so a multi-container denial stays legible.
func mergeExplanation(acc, add *policy.Explanation, image string) *policy.Explanation {
	if add == nil {
		return acc
	}
	tag := func(rs []policy.RuleExplanation) []policy.RuleExplanation {
		if image == "" {
			return rs
		}
		out := make([]policy.RuleExplanation, len(rs))
		for i, r := range rs {
			r.Reason = "[" + image + "] " + r.Reason
			out[i] = r
		}
		return out
	}
	if acc == nil {
		acc = &policy.Explanation{Policy: add.Policy, Decision: add.Decision, EvaluatedAt: add.EvaluatedAt}
	}
	// The aggregate decision is the worst seen so far.
	if add.Decision == policy.DecisionDeny || (add.Decision == policy.DecisionWarn && acc.Decision == policy.DecisionAllow) {
		acc.Decision = add.Decision
	}
	acc.Denials = append(acc.Denials, tag(add.Denials)...)
	acc.Warnings = append(acc.Warnings, tag(add.Warnings)...)
	acc.Remediation = dedupeStrings(append(acc.Remediation, add.Remediation...))
	acc.Summary = fmt.Sprintf("%s by policy %q: %d denial(s)", strings.ToUpper(string(acc.Decision)), acc.Policy, len(acc.Denials))
	return acc
}

func dedupeStrings(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Policy test harness ---------------------------------------------------
//
// Policies are code, so they get unit tests. A Suite is a committed file of
// cases: each names an Input and the Decision it must produce (and, optionally,
// exactly which rules must fire). `dsecrat policy test` runs the suite and fails CI
// if a policy change silently flips a gate — the same safety net application
// code gets, applied to the rules that guard deploys.

// Suite is a policy test file.
type Suite struct {
	// Policy is the path to the policy under test, relative to the suite file.
	Policy string `json:"policy"`
	// Cases are the individual test cases.
	Cases []Case `json:"cases"`
}

// Case is one policy test: given Input at time Now, expect Decision.
type Case struct {
	Name string `json:"name"`
	// Now is the evaluation time (RFC3339). Empty uses the suite's default,
	// keeping waiver-expiry tests deterministic and independent of the wall clock.
	Now string `json:"now,omitempty"`
	// Input is the world to evaluate.
	Input CaseInput `json:"input"`
	// Expect is the required aggregate decision.
	Expect DecisionType `json:"expect"`
	// ExpectFiring, when set, is the exact set of rule ids that must fire
	// unwaived (order-independent). Nil means "do not check individual rules".
	ExpectFiring []string `json:"expect_firing,omitempty"`
}

// CaseInput is the JSON-friendly form of an Input (string severities, a static
// attestation state) that a suite file can express directly.
type CaseInput struct {
	Findings []FindingJSON     `json:"findings,omitempty"`
	Image    Image             `json:"image,omitempty"`
	Workload Workload          `json:"workload,omitempty"`
	Attest   StaticAttestation `json:"attest,omitempty"`
	Licenses []string          `json:"licenses,omitempty"`
	Packages []string          `json:"packages,omitempty"`
}

// toInput materializes the evaluation Input.
func (c CaseInput) toInput() *Input {
	fs := make([]engine.Finding, len(c.Findings))
	for i, f := range c.Findings {
		fs[i] = f.toFinding()
	}
	return &Input{
		Findings: fs,
		Image:    c.Image,
		Workload: c.Workload,
		Attest:   c.Attest,
		Licenses: c.Licenses,
		Packages: c.Packages,
	}
}

// ParseSuite decodes a suite file.
func ParseSuite(data []byte) (*Suite, error) {
	var s Suite
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse policy test suite: %w", err)
	}
	if len(s.Cases) == 0 {
		return nil, fmt.Errorf("policy test suite has no cases")
	}
	return &s, nil
}

// CaseResult is the outcome of one case.
type CaseResult struct {
	Name   string       `json:"name"`
	Pass   bool         `json:"pass"`
	Want   DecisionType `json:"want"`
	Got    DecisionType `json:"got"`
	Detail string       `json:"detail,omitempty"`
}

// SuiteResult aggregates a run.
type SuiteResult struct {
	Results []CaseResult `json:"results"`
	Passed  int          `json:"passed"`
	Failed  int          `json:"failed"`
}

// OK reports whether every case passed.
func (s SuiteResult) OK() bool { return s.Failed == 0 }

// RunSuite evaluates every case against the compiled engine. defaultNow is used
// for cases that do not pin their own Now.
func (e *Engine) RunSuite(cases []Case, defaultNow time.Time) SuiteResult {
	var sr SuiteResult
	for _, c := range cases {
		now := defaultNow
		if c.Now != "" {
			if t, err := time.Parse(time.RFC3339, c.Now); err == nil {
				now = t
			}
		}
		res := e.Evaluate(c.Input.toInput(), now)
		cr := CaseResult{Name: c.Name, Want: c.Expect, Got: res.Decision, Pass: true}

		if res.Decision != c.Expect {
			cr.Pass = false
			cr.Detail = fmt.Sprintf("decision = %s, want %s", res.Decision, c.Expect)
		} else if c.ExpectFiring != nil {
			if diff := firingDiff(res, c.ExpectFiring); diff != "" {
				cr.Pass = false
				cr.Detail = diff
			}
		}

		if cr.Pass {
			sr.Passed++
		} else {
			sr.Failed++
		}
		sr.Results = append(sr.Results, cr)
	}
	return sr
}

// firingDiff compares the rules that actually fired (unwaived) against the
// expected set, returning a human diff or "" when they match.
func firingDiff(res *Result, want []string) string {
	got := map[string]bool{}
	for _, rr := range res.Firing(false) {
		got[rr.RuleID] = true
	}
	wantSet := map[string]bool{}
	for _, id := range want {
		wantSet[id] = true
	}
	var missing, extra []string
	for id := range wantSet {
		if !got[id] {
			missing = append(missing, id)
		}
	}
	for id := range got {
		if !wantSet[id] {
			extra = append(extra, id)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return fmt.Sprintf("firing mismatch: missing %v, unexpected %v", missing, extra)
}

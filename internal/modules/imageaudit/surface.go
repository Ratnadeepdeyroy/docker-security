package imageaudit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Attack-surface score (AI-age enrichment, off by default) ----------------
//
// This is the module's "leap beyond parity": a composite, explainable
// attack-surface score plus a structured hardening plan an AI agent can consume
// and act on ("switch base to distroless, drop USER to non-root, strip N setuid
// bits — expected surface reduction ..."). It is emitted only when the module
// is built WithAttackSurfaceScore(): it is opinionated enrichment layered on top
// of the deterministic CIS core, and per SHARED_CONTRACT §4 correctness must
// never depend on it. The computation itself is pure and deterministic — no
// clock, no randomness — so the score is reproducible and testable.

// surfaceFactor is one weighted contributor to the score, with the human and
// machine rationale for why it counts.
type surfaceFactor struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
	Detail string `json:"detail"`
}

// hardeningStep is a single agent-appliable remediation with its expected
// impact, so automation can prioritize and (eventually) apply fixes.
type hardeningStep struct {
	Action string `json:"action"`
	Why    string `json:"why"`
	Impact string `json:"impact"`
}

// hardeningPlan is the machine-consumable payload attached to DS-RAT-IMG-100.
type hardeningPlan struct {
	Score      int             `json:"attack_surface_score"` // 0 (minimal) .. 100 (maximal)
	Grade      string          `json:"grade"`
	Distroless bool            `json:"distroless"`
	Factors    []surfaceFactor `json:"factors"`
	Steps      []hardeningStep `json:"steps"`
}

// scoreWeights centralizes the point cost of each surface factor. Weights are
// intentionally coarse and documented; the score is a prioritization aid, not a
// precise metric, and keeping the numbers here makes it easy to tune with a
// test.
const (
	wRoot        = 30
	wShell       = 15
	wPkgMgr      = 15
	wSetuidEach  = 3
	wSetuidCap   = 20
	wNoHealth    = 5
	wSSHPort     = 10
	wPrivPort    = 5
	wSecretEnv   = 15
	wPrivPortCap = 10
)

// surfaceFinding computes the score and hardening plan and packages them as a
// single INFO finding. INFO keeps it gating-neutral: it informs and enables
// automation without failing a build on its own.
func surfaceFinding(ac *auditContext) engine.Finding {
	plan := buildPlan(ac)

	planJSON, _ := json.Marshal(plan) // marshal of plain structs cannot fail
	meta := map[string]string{
		"attack_surface_score": strconv.Itoa(plan.Score),
		"grade":                plan.Grade,
		"distroless":           strconv.FormatBool(plan.Distroless),
		"shell_present":        strconv.FormatBool(len(ac.probe.shells) > 0),
		"pkg_manager_present":  strconv.FormatBool(len(ac.probe.pkgMgrs) > 0),
		"setuid_count":         strconv.Itoa(ac.probe.setuidN),
		"hardening_plan":       string(planJSON),
	}

	return engine.Finding{
		RuleID:      "DS-RAT-IMG-100",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       fmt.Sprintf("Attack-surface score %d/100 (%s)", plan.Score, plan.Grade),
		Description: humanSummary(plan),
		Resource:    ac.name,
		Remediation: "Apply the ordered hardening_plan in this finding's metadata; each step lists its expected surface reduction.",
		References:  []string{"NIST-SP-800-190", "CIS-DI-0008"},
		Metadata:    meta,
	}
}

// buildPlan is the pure core: it turns the audit context into a score and an
// ordered remediation plan. Factors are appended in a fixed order so the output
// is deterministic.
func buildPlan(ac *auditContext) hardeningPlan {
	var plan hardeningPlan
	add := func(name string, pts int, detail string) {
		plan.Factors = append(plan.Factors, surfaceFactor{Name: name, Points: pts, Detail: detail})
		plan.Score += pts
	}

	root, explicit := ac.cfg.Config.runsAsRoot()
	if root {
		state := "no USER set"
		if explicit {
			state = "USER " + ac.cfg.Config.User
		}
		add("runs_as_root", wRoot, "container runs as UID 0 ("+state+")")
		plan.Steps = append(plan.Steps, hardeningStep{
			Action: "set a non-root USER (e.g. a dedicated UID like 65532)",
			Why:    "root in-container is root at the kernel boundary on escape",
			Impact: fmt.Sprintf("-%d surface points", wRoot),
		})
	}

	if len(ac.probe.shells) > 0 {
		add("shell_present", wShell, "shells: "+strings.Join(ac.probe.shells, ", "))
		plan.Steps = append(plan.Steps, hardeningStep{
			Action: "move to a distroless/scratch runtime base so no shell ships",
			Why:    "a shell is the usual pivot for command injection and post-exploitation",
			Impact: fmt.Sprintf("-%d surface points; removes %d shell binaries", wShell, len(ac.probe.shells)),
		})
	}

	if len(ac.probe.pkgMgrs) > 0 {
		add("package_manager_present", wPkgMgr, "managers: "+strings.Join(ac.probe.pkgMgrs, ", "))
		plan.Steps = append(plan.Steps, hardeningStep{
			Action: "use a multi-stage build; keep the package manager out of the runtime stage",
			Why:    "a package manager lets a compromised process install new tooling in place",
			Impact: fmt.Sprintf("-%d surface points", wPkgMgr),
		})
	}

	if ac.probe.setuidN > 0 {
		pts := ac.probe.setuidN * wSetuidEach
		if pts > wSetuidCap {
			pts = wSetuidCap
		}
		add("setuid_binaries", pts, fmt.Sprintf("%d setuid binaries", ac.probe.setuidN))
		plan.Steps = append(plan.Steps, hardeningStep{
			Action: "strip setuid bits (chmod u-s) or remove the binaries; prefer capabilities",
			Why:    "each setuid binary is a local privilege-escalation primitive",
			Impact: fmt.Sprintf("-%d surface points; neutralizes %d escalation primitives", pts, ac.probe.setuidN),
		})
	}

	if !ac.cfg.Config.hasHealthcheck() {
		add("no_healthcheck", wNoHealth, "no HEALTHCHECK configured")
		plan.Steps = append(plan.Steps, hardeningStep{
			Action: "add a HEALTHCHECK that probes the primary process",
			Why:    "runtimes cannot detect a wedged container without one",
			Impact: fmt.Sprintf("-%d surface points", wNoHealth),
		})
	}

	if hasSecretEnv(ac) {
		add("secret_in_env", wSecretEnv, "credential-shaped variable in image ENV")
		plan.Steps = append(plan.Steps, hardeningStep{
			Action: "remove secrets from ENV; inject at runtime and rotate the value",
			Why:    "anyone who can pull the image can read ENV, and it persists in history",
			Impact: fmt.Sprintf("-%d surface points", wSecretEnv),
		})
	}

	if pts, detail := portPoints(ac); pts > 0 {
		add("exposed_port", pts, detail)
		plan.Steps = append(plan.Steps, hardeningStep{
			Action: "drop privileged/SSH port exposure; use exec for debugging, high ports for services",
			Why:    "privileged and SSH ports widen the network attack surface",
			Impact: fmt.Sprintf("-%d surface points", pts),
		})
	}

	if plan.Score > 100 {
		plan.Score = 100
	}
	plan.Grade = grade(plan.Score)
	plan.Distroless = len(ac.probe.shells) == 0 && len(ac.probe.pkgMgrs) == 0
	return plan
}

// hasSecretEnv reports whether any env var trips the secret heuristic.
func hasSecretEnv(ac *auditContext) bool {
	for _, kv := range ac.cfg.Config.Env {
		if ok, _ := secretEnv(splitEnv(kv)); ok {
			return true
		}
	}
	return false
}

// portPoints scores exposed ports: an SSH port dominates, otherwise privileged
// ports contribute up to a cap. It returns the points and a human detail.
func portPoints(ac *auditContext) (int, string) {
	ssh := false
	priv := 0
	for _, spec := range ac.cfg.Config.sortedPorts() {
		portStr, _, _ := strings.Cut(spec, "/")
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil {
			continue
		}
		if port == 22 {
			ssh = true
		} else if port < 1024 {
			priv++
		}
	}
	pts := 0
	var details []string
	if ssh {
		pts += wSSHPort
		details = append(details, "SSH port exposed")
	}
	if priv > 0 {
		p := priv * wPrivPort
		if p > wPrivPortCap {
			p = wPrivPortCap
		}
		pts += p
		details = append(details, fmt.Sprintf("%d privileged ports exposed", priv))
	}
	sort.Strings(details)
	return pts, strings.Join(details, "; ")
}

// grade maps a score to a coarse letter, so a human sees posture at a glance.
func grade(score int) string {
	switch {
	case score <= 10:
		return "A"
	case score <= 30:
		return "B"
	case score <= 50:
		return "C"
	case score <= 75:
		return "D"
	default:
		return "F"
	}
}

// humanSummary renders the plan as a readable paragraph for the Description.
func humanSummary(plan hardeningPlan) string {
	var b strings.Builder
	if plan.Distroless {
		fmt.Fprintf(&b, "Distroless/minimal runtime. ")
	}
	fmt.Fprintf(&b, "Composite attack-surface score %d/100 (grade %s), from %d factor(s): ",
		plan.Score, plan.Grade, len(plan.Factors))
	if len(plan.Factors) == 0 {
		b.WriteString("none — no scored surface detected. ")
	} else {
		parts := make([]string, 0, len(plan.Factors))
		for _, f := range plan.Factors {
			parts = append(parts, fmt.Sprintf("%s (+%d)", f.Name, f.Points))
		}
		b.WriteString(strings.Join(parts, ", "))
		b.WriteString(". ")
	}
	if len(plan.Steps) > 0 {
		fmt.Fprintf(&b, "%d hardening step(s) proposed in metadata.hardening_plan for an agent to apply.", len(plan.Steps))
	} else {
		b.WriteString("No hardening steps needed.")
	}
	return b.String()
}

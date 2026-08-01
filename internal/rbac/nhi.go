package rbac

import (
	"fmt"
	"sort"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file implements the Non-Human-Identity (NHI) risk graph — the phase's
// AI-age leap, and OFF BY DEFAULT (it runs only when Options.EnableNHI is set).
// Machine and agent identities now vastly outnumber humans and are the least
// reviewed identity class, yet a prompt-injected agent holding a ServiceAccount
// token is as dangerous as a compromised admin. This pass treats every
// ServiceAccount as a first-class principal: it scores each one's blast radius
// (how far it can reach, how many namespaces it touches, whether it reaches a
// terminal target) and flags the two failure modes that matter most — dormant
// automation identities that still hold broad power, and identities whose blast
// radius is disproportionate to their use. It is deterministic: "now" and the
// dormancy threshold are injected via Options, never read from the wall clock.

// --- Blast-radius scoring ------------------------------------------------

// nhiScore is the computed risk profile of one non-human identity.
type nhiScore struct {
	subjectKey    string
	reachesTarget string // "" if it reaches no terminal target
	reachCount    int    // distinct principals+targets reachable
	namespaces    map[string]struct{}
	dormant       bool
	lastUsed      int64
}

// checkNHI scores every ServiceAccount identity and emits findings for dormant or
// over-broad automation identities. Human subjects (User/Group) are intentionally
// out of scope here — this pass is about the machine identities that slip through
// human-centric reviews.
func checkNHI(c *Cluster, g *Graph, opts Options) []Risk {
	adj := buildEscalationEdges(c, g)
	dormantAfter := opts.dormantAfter()
	now := opts.now()

	var rs []Risk
	for _, sk := range serviceAccountSubjectKeys(g) {
		score := scoreIdentity(c, g, adj, sk, now, dormantAfter)

		// Dormant + still powerful: the fastest-growing, least-reviewed risk.
		if score.dormant && (score.reachesTarget != "" || score.reachCount >= opts.broadThreshold()) {
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-018",
				Severity:    engine.SeverityHigh,
				Title:       fmt.Sprintf("Dormant automation identity %s still holds broad access", label(sk)),
				Description: dormancyDesc(score, now),
				Subject:     sk,
				Remediation: "Disable or delete unused ServiceAccounts; rotate their tokens. An unused identity with cluster reach is pure attack surface.",
				References:  []string{refK8sHarden, refNISTac6},
				Meta:        nhiMeta(score),
			})
			continue
		}
		// Over-broad automation identity (blast radius too large), regardless of use.
		if score.reachesTarget != "" || score.reachCount >= opts.broadThreshold() {
			sev := engine.SeverityMedium
			if score.reachesTarget == "cluster-admin" {
				sev = engine.SeverityCritical
			} else if score.reachesTarget != "" {
				sev = engine.SeverityHigh
			}
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-018",
				Severity:    sev,
				Title:       fmt.Sprintf("Over-broad automation identity %s (blast radius %d)", label(sk), score.reachCount),
				Description: blastDesc(score),
				Subject:     sk,
				Remediation: "Split this identity per task and scope each with the least-privilege role (see generated role); if an AI agent holds this token, constrain what it can do when prompt-injected.",
				References:  []string{refK8sHarden, refNISTac6},
				Meta:        nhiMeta(score),
			})
		}
	}
	return dedupe(rs)
}

// scoreIdentity computes the blast radius of one identity via BFS over the
// escalation graph (reusing the same edges the path analysis uses, so the two
// stay consistent), plus dormancy from injected time.
func scoreIdentity(c *Cluster, g *Graph, adj map[string][]escEdge, sk string, now time.Time, dormantAfter time.Duration) nhiScore {
	s := nhiScore{subjectKey: sk, namespaces: map[string]struct{}{}}

	// Reachability (bounded BFS over all edges, not just to a target).
	visited := map[string]bool{sk: true}
	queue := []string{sk}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range adj[cur] {
			if e.to == targetClusterAdmin || e.to == targetNodeRoot {
				if s.reachesTarget == "" || e.to == targetClusterAdmin {
					s.reachesTarget = prettyTarget(e.to)
				}
				continue
			}
			if visited[e.to] {
				continue
			}
			visited[e.to] = true
			s.reachCount++
			queue = append(queue, e.to)
		}
	}
	if s.reachesTarget != "" {
		s.reachCount++ // count the terminal in the blast radius
	}

	// Namespaces the identity's grants touch (breadth of reach).
	for _, gr := range g.Grants {
		if gr.Subject.key() == sk {
			ns := gr.Namespace
			if ns == "" {
				ns = "*cluster*"
			}
			s.namespaces[ns] = struct{}{}
		}
	}

	// Dormancy from the SA record's LastUsedUnix (audit-usage annotation).
	if sa := lookupSA(c, sk); sa != nil && sa.LastUsedUnix > 0 {
		s.lastUsed = sa.LastUsedUnix
		if now.Sub(time.Unix(sa.LastUsedUnix, 0)) > dormantAfter {
			s.dormant = true
		}
	}
	return s
}

// --- Descriptions & metadata ---------------------------------------------

func dormancyDesc(s nhiScore, now time.Time) string {
	idle := now.Sub(time.Unix(s.lastUsed, 0))
	reach := "no terminal target"
	if s.reachesTarget != "" {
		reach = "reaches " + s.reachesTarget
	}
	return fmt.Sprintf("last used %s ago (%d days); blast radius %d, %s across %d namespace(s)",
		idle.Round(time.Hour), int(idle.Hours()/24), s.reachCount, reach, len(s.namespaces))
}

func blastDesc(s nhiScore) string {
	reach := "no terminal target"
	if s.reachesTarget != "" {
		reach = "can escalate to " + s.reachesTarget
	}
	return fmt.Sprintf("blast radius %d principals across %d namespace(s); %s",
		s.reachCount, len(s.namespaces), reach)
}

func nhiMeta(s nhiScore) map[string]string {
	m := map[string]string{
		"blastRadius": fmt.Sprintf("%d", s.reachCount),
		"namespaces":  fmt.Sprintf("%d", len(s.namespaces)),
		"dormant":     fmt.Sprintf("%t", s.dormant),
	}
	if s.reachesTarget != "" {
		m["reachesTarget"] = s.reachesTarget
	}
	if s.lastUsed > 0 {
		m["lastUsedUnix"] = fmt.Sprintf("%d", s.lastUsed)
	}
	return m
}

// --- Small helpers -------------------------------------------------------

func lookupSA(c *Cluster, subjectKey string) *ServiceAccount {
	for _, sa := range c.ServiceAccounts {
		if (Subject{Kind: "ServiceAccount", Name: sa.Name, Namespace: sa.Namespace}).key() == subjectKey {
			return sa
		}
	}
	return nil
}

func label(subjectKey string) string { return subjectKey }

// sortedNamespaces is used by tests/reporting to render an identity's reach.
func (s nhiScore) sortedNamespaces() []string {
	out := make([]string, 0, len(s.namespaces))
	for ns := range s.namespaces {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

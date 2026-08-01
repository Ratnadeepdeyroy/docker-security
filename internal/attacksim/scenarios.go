package attacksim

import "sort"

// This file is the curated catalog of safe adversary scenarios, each mapped to a
// MITRE ATT&CK-for-Containers technique. Every scenario is an inert descriptor:
// the Attributes are the bad properties a control should catch, not instructions
// to do anything. Adding a scenario is a data-only change here — the harness and
// reports pick it up automatically. IDs are stable (DS-RAT-ATK-NNN) so findings and
// baselines stay comparable across releases.

// Builtin returns the standard scenario catalog, sorted by ID for determinism.
// Callers may pass a subset to the harness, but the default is the full set.
func Builtin() []Scenario {
	s := []Scenario{
		{
			ID: "DS-RAT-ATK-001", Technique: "T1610", TacticName: "Execution",
			Name: "Deploy privileged container", Expect: KindAdmission, Severity: "CRITICAL",
			Description: "Create a pod with a privileged container — full host device access, the most common escape primitive.",
			Event: Event{Technique: "T1610", Tactic: "Execution", Action: "create privileged pod", Target: "pod/attacker",
				Attributes: map[string]string{"privileged": "true"}},
			References: []string{"https://attack.mitre.org/techniques/T1610/"},
		},
		{
			ID: "DS-RAT-ATK-002", Technique: "T1611", TacticName: "Privilege Escalation",
			Name: "Mount host root filesystem", Expect: KindAdmission, Severity: "CRITICAL",
			Description: "Create a pod with a hostPath volume mounting '/', giving read/write to the node's filesystem.",
			Event: Event{Technique: "T1611", Tactic: "Privilege Escalation", Action: "hostPath mount /", Target: "pod/attacker",
				Attributes: map[string]string{"hostPath": "/"}},
			References: []string{"https://attack.mitre.org/techniques/T1611/"},
		},
		{
			ID: "DS-RAT-ATK-003", Technique: "T1611", TacticName: "Privilege Escalation",
			Name: "Share host namespaces", Expect: KindAdmission, Severity: "HIGH",
			Description: "Create a pod with hostPID/hostNetwork, exposing host processes and the node network to the container.",
			Event: Event{Technique: "T1611", Tactic: "Privilege Escalation", Action: "hostPID+hostNetwork pod", Target: "pod/attacker",
				Attributes: map[string]string{"hostPID": "true", "hostNetwork": "true"}},
			References: []string{"https://attack.mitre.org/techniques/T1611/"},
		},
		{
			ID: "DS-RAT-ATK-004", Technique: "T1610", TacticName: "Execution",
			Name: "Mount the Docker socket", Expect: KindAdmission, Severity: "CRITICAL",
			Description: "Create a pod that bind-mounts /var/run/docker.sock — control of the daemon equals control of the host.",
			Event: Event{Technique: "T1610", Tactic: "Execution", Action: "mount docker.sock", Target: "pod/ci-runner",
				Attributes: map[string]string{"mountsDockerSocket": "true"}},
			References: []string{"https://attack.mitre.org/techniques/T1610/"},
		},
		{
			ID: "DS-RAT-ATK-005", Technique: "T1611", TacticName: "Privilege Escalation",
			Name: "Add CAP_SYS_ADMIN", Expect: KindAdmission, Severity: "HIGH",
			Description: "Create a pod adding a dangerous Linux capability (e.g. SYS_ADMIN), a near-privileged escape surface.",
			Event: Event{Technique: "T1611", Tactic: "Privilege Escalation", Action: "add SYS_ADMIN capability", Target: "pod/attacker",
				Attributes: map[string]string{"addedCapability": "SYS_ADMIN"}},
			References: []string{"https://attack.mitre.org/techniques/T1611/"},
		},
		{
			ID: "DS-RAT-ATK-006", Technique: "T1613", TacticName: "Discovery",
			Name: "Enable privilege escalation flag", Expect: KindAdmission, Severity: "MEDIUM",
			Description: "Create a container with allowPrivilegeEscalation:true, permitting setuid-based escalation inside the container.",
			Event: Event{Technique: "T1613", Tactic: "Discovery", Action: "allowPrivilegeEscalation", Target: "pod/attacker",
				Attributes: map[string]string{"allowPrivilegeEscalation": "true"}},
			References: []string{"https://attack.mitre.org/techniques/T1613/"},
		},
		{
			ID: "DS-RAT-ATK-007", Technique: "T1609", TacticName: "Execution",
			Name: "Exec into a running container", Expect: KindDetection, Severity: "HIGH",
			Description: "kubectl exec / docker exec into a running container — interactive access an attacker uses post-compromise.",
			Event: Event{Technique: "T1609", Tactic: "Execution", Action: "exec into container", Target: "pod/payments",
				Attributes: map[string]string{"execIntoContainer": "true"}},
			References: []string{"https://attack.mitre.org/techniques/T1609/"},
		},
		{
			ID: "DS-RAT-ATK-008", Technique: "T1552.001", TacticName: "Credential Access",
			Name: "Read the ServiceAccount token", Expect: KindDetection, Severity: "HIGH",
			Description: "Read /var/run/secrets/kubernetes.io/serviceaccount/token — credential theft from inside a pod.",
			Event: Event{Technique: "T1552.001", Tactic: "Credential Access", Action: "read SA token file", Target: "pod/payments",
				Attributes: map[string]string{"readServiceAccountToken": "true"}},
			References: []string{"https://attack.mitre.org/techniques/T1552/001/"},
		},
		{
			ID: "DS-RAT-ATK-009", Technique: "T1496", TacticName: "Impact",
			Name: "Spawn a crypto-miner", Expect: KindDetection, Severity: "HIGH",
			Description: "Launch a mining process (e.g. xmrig) — the classic resource-hijacking payload after a container is popped.",
			Event: Event{Technique: "T1496", Tactic: "Impact", Action: "spawn miner", Target: "pod/web",
				Attributes: map[string]string{"spawnsCryptominer": "true"}},
			References: []string{"https://attack.mitre.org/techniques/T1496/"},
		},
		{
			ID: "DS-RAT-ATK-010", Technique: "T1059", TacticName: "Execution",
			Name: "Open a reverse shell", Expect: KindDetection, Severity: "CRITICAL",
			Description: "Establish outbound interactive egress (reverse shell) from a container — command-and-control.",
			Event: Event{Technique: "T1059", Tactic: "Execution", Action: "reverse shell egress", Target: "pod/web",
				Attributes: map[string]string{"reverseShell": "true"}},
			References: []string{"https://attack.mitre.org/techniques/T1059/"},
		},
	}
	sort.Slice(s, func(i, j int) bool { return s[i].ID < s[j].ID })
	return s
}

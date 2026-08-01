package runtime

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file holds file-integrity monitoring (FIM) and credential-theft rules.
// FIM watches for tampering with system files; credential theft watches for
// reads of the specific secrets attackers pivot on (SA tokens, cloud creds, SSH
// keys) whether they are grabbed from disk or from the metadata service.

// --- DS-RAT-RT-004 sensitive-file access (FIM) -------------------------------

type sensitiveFileRule struct{ ruleBase }

func newSensitiveFileRule() Rule {
	return &sensitiveFileRule{ruleBase{
		id: "DS-RAT-RT-004",
		info: RuleInfo{
			Title:       "Sensitive file access",
			Severity:    engine.SeverityMedium,
			Technique:   techUnsecuredCred,
			Default:     true,
			Description: "A process read a sensitive file (e.g. /etc/shadow) or modified a security-critical file (e.g. /etc/passwd, sudoers, authorized_keys, ld.so.preload). Writes are treated as tampering/persistence and scored higher than reads.",
			Remediation: "Enforce a read-only root filesystem and least-privilege file permissions. Alert on and investigate any write to system-critical paths; validate against expected configuration management.",
		},
	}}
}

func (r *sensitiveFileRule) Evaluate(ev *Event, st *State) []Detection {
	if ev.Kind != KindFile || ev.File == nil {
		return nil
	}
	isWrite := fileIsWrite(ev.File)

	// Writes to security-critical paths — tampering / persistence (higher risk).
	if isWrite {
		if pre, ok := matchesAnyPrefix(ev.File.Path, sensitiveWritePaths); ok {
			d := r.fire(ev, "write to security-critical file "+ev.File.Path+" ("+ev.File.Op+")",
				map[string]string{"path": ev.File.Path, "op": ev.File.Op, "matched": pre, "access": "write"})
			d.Severity = engine.SeverityHigh // escalate: modification beats read
			return []Detection{d}
		}
	}

	// Reads of sensitive files — recon (baseline severity), incl. SSH keys.
	if isSSHKeyPath(ev.File.Path) {
		return []Detection{r.fire(ev, "read of private SSH key "+ev.File.Path,
			map[string]string{"path": ev.File.Path, "op": ev.File.Op, "access": "read"})}
	}
	if pre, ok := matchesAnyPrefix(ev.File.Path, sensitiveReadPaths); ok {
		return []Detection{r.fire(ev, "access to sensitive file "+ev.File.Path+" ("+ev.File.Op+")",
			map[string]string{"path": ev.File.Path, "op": ev.File.Op, "matched": pre, "access": "read"})}
	}
	return nil
}

// fileIsWrite reports whether a file op mutates the file.
func fileIsWrite(f *FileEvent) bool {
	switch f.Op {
	case "write", "unlink", "rename", "truncate", "chmod", "chown", "create":
		return true
	}
	// open with a write flag counts as a write intent.
	return strings.Contains(f.Flags, "O_WRONLY") || strings.Contains(f.Flags, "O_RDWR") || strings.Contains(f.Flags, "O_CREAT")
}

// --- DS-RAT-RT-005 credential / token / IMDS theft ---------------------------

type credTheftRule struct{ ruleBase }

func newCredTheftRule() Rule {
	return &credTheftRule{ruleBase{
		id: "DS-RAT-RT-005",
		info: RuleInfo{
			Title:       "Credential / token theft",
			Severity:    engine.SeverityHigh,
			Technique:   techCloudIMDS,
			Default:     true,
			Description: "A process accessed high-value credentials: a Kubernetes service-account token, cloud credential files, or the cloud instance-metadata service (IMDS, 169.254.169.254). This is the pivot from a compromised container to the cloud account.",
			Remediation: "Enforce IMDSv2 with a hop limit of 1 and block IMDS egress from pods that do not need it. Mount SA tokens only where required (`automountServiceAccountToken: false`). Rotate any token that may have been exposed.",
		},
	}}
}

func (r *credTheftRule) Evaluate(ev *Event, st *State) []Detection {
	switch ev.Kind {
	case KindFile:
		if ev.File == nil {
			return nil
		}
		if pre, ok := matchesAnyPrefix(ev.File.Path, credentialPaths); ok {
			meta := map[string]string{"path": ev.File.Path, "op": ev.File.Op, "matched": pre, "vector": "file"}
			d := r.fire(ev, "access to credential store "+ev.File.Path, meta)
			// A Kubernetes/EKS service-account token read is specifically
			// application-token theft (T1528); other credential files are the
			// broader unsecured-credentials technique.
			if strings.Contains(pre, "serviceaccount/token") {
				d.Technique = techStealToken
			} else {
				d.Technique = techUnsecuredCred
			}
			d.References = []string{d.Technique.URL}
			return []Detection{d}
		}
	case KindNetwork:
		if ev.Network == nil {
			return nil
		}
		if isIMDS(ev.Network) {
			ep := endpointKey(ev.Network)
			meta := map[string]string{"endpoint": ep, "vector": "imds"}
			return []Detection{r.fire(ev, "connection to cloud metadata service ("+ep+") — possible credential theft", meta)}
		}
	}
	return nil
}

// isIMDS reports whether a network event targets a cloud metadata endpoint.
func isIMDS(n *NetworkEvent) bool {
	if _, ok := imdsIPs[n.RemoteIP]; ok {
		return true
	}
	if n.Domain != "" {
		if _, ok := imdsDomains[strings.ToLower(n.Domain)]; ok {
			return true
		}
	}
	return false
}

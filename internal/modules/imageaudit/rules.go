package imageaudit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// rule inspects a fully-loaded image and returns any findings.
type rule func(ac *auditContext) []engine.Finding

// coreRules is the deterministic CIS/best-practice rule set. Order here only
// affects construction; Analyze re-sorts the merged findings for a stable
// output. Adding a rule to this slice wires it into the module.
var coreRules = []rule{
	ruleRootUser,           // DS-RAT-IMG-001  CIS-DI-0001
	ruleHealthcheck,        // DS-RAT-IMG-002  CIS-DI-0006
	ruleSecretsInEnv,       // DS-RAT-IMG-003  CIS-DI-0010
	ruleImageTag,           // DS-RAT-IMG-004  CIS-DI-0005/0006
	ruleSetuid,             // DS-RAT-IMG-005  CIS-DI-0008
	rulePorts,              // DS-RAT-IMG-006  domain 10
	ruleVolumes,            // DS-RAT-IMG-007  domain 10
	ruleProvenanceLabels,   // DS-RAT-IMG-008  provenance
	ruleHistory,            // DS-RAT-IMG-009  CIS-DI-0010 / best-practice
	rulePackageManager,     // DS-RAT-IMG-010  attack surface
	ruleShellSurface,       // DS-RAT-IMG-011  attack surface / distroless reward
	ruleRecoverableRemoved, // DS-RAT-IMG-012  CIS-DI-0010 (layer history)
}

// --- DS-RAT-IMG-001: runs as root ------------------------------------------------

// ruleRootUser flags an image whose configured user is root. An unset user is
// scored MEDIUM (implicit — easy to fix, and some runtimes override it) while
// an explicit root/0 is HIGH (a deliberate, load-bearing choice). CIS-DI-0001.
func ruleRootUser(ac *auditContext) []engine.Finding {
	root, explicit := ac.cfg.Config.runsAsRoot()
	if !root {
		return nil
	}
	if explicit {
		return []engine.Finding{mk("DS-RAT-IMG-001", engine.SeverityHigh, ac.name,
			"Image explicitly configured to run as root",
			fmt.Sprintf("The image config sets USER %q, so the entrypoint runs with in-container UID 0. A container escape then starts from root.", ac.cfg.Config.User),
			"Add a dedicated non-root user to the image and set USER to its UID before the final ENTRYPOINT/CMD.",
			"CIS-DI-0001", "NIST-SP-800-190")}
	}
	return []engine.Finding{mk("DS-RAT-IMG-001", engine.SeverityMedium, ac.name,
		"Image runs as root (no USER configured)",
		"The image config declares no USER, so the container defaults to UID 0. Running as root widens the blast radius of any process compromise.",
		"Create a non-root user in the image and set USER to its UID; verify with `docker inspect`.",
		"CIS-DI-0001", "NIST-SP-800-190")}
}

// --- DS-RAT-IMG-002: HEALTHCHECK -------------------------------------------------

// ruleHealthcheck flags the absence of a configured HEALTHCHECK. Without one an
// orchestrator cannot tell a wedged container from a healthy one. CIS-DI-0006.
func ruleHealthcheck(ac *auditContext) []engine.Finding {
	if ac.cfg.Config.hasHealthcheck() {
		return nil
	}
	return []engine.Finding{mk("DS-RAT-IMG-002", engine.SeverityLow, ac.name,
		"No HEALTHCHECK configured in image",
		"The image config carries no HEALTHCHECK (or it is set to NONE), so runtimes cannot detect an unhealthy-but-running process.",
		"Bake a HEALTHCHECK into the image that probes the primary process, or define one in the orchestrator.",
		"CIS-DI-0006")}
}

// --- DS-RAT-IMG-003: secrets in ENV ----------------------------------------------

// ruleSecretsInEnv flags credential-shaped environment variables baked into the
// image config. Anyone who can pull the image can read these with a single
// `docker inspect`; they also persist in every layer's history. CIS-DI-0010.
func ruleSecretsInEnv(ac *auditContext) []engine.Finding {
	var out []engine.Finding
	for _, kv := range ac.cfg.Config.Env {
		key, value := splitEnv(kv)
		if ok, why := secretEnv(key, value); ok {
			out = append(out, mk("DS-RAT-IMG-003", engine.SeverityHigh, ac.name,
				"Possible secret baked into image ENV ("+key+")",
				fmt.Sprintf("Environment variable %q looks like a credential: %s. It is readable by anyone who can pull the image and is preserved in layer history.", key, why),
				"Remove the secret from the image and inject it at runtime (orchestrator secret, mounted file, or vault); rotate the exposed value.",
				"CIS-DI-0010", "NIST-SP-800-190"))
		}
	}
	return out
}

// --- DS-RAT-IMG-004: image tag ---------------------------------------------------

// ruleImageTag flags a repo tag that tracks a moving target (:latest or no tag).
// Deploying such a tag means you cannot say which bits are actually running.
// CIS-DI-0005 (content trust) / CIS-DI-0006.
func ruleImageTag(ac *auditContext) []engine.Finding {
	var out []engine.Finding
	seen := map[string]bool{}
	for _, ref := range ac.img.RepoTags {
		tag := refTag(ref)
		var title, desc string
		switch tag {
		case "":
			title = "Image is untagged (implicit :latest)"
			desc = "The image reference " + ref + " has no explicit tag, so it resolves to a moving :latest. Deployments are not reproducible and cannot be verified against a known-good build."
		case "latest":
			title = "Image tagged :latest"
			desc = "The image reference " + ref + " uses the moving :latest tag; the bits behind it can change between pulls, defeating content verification."
		default:
			continue
		}
		if seen[title] {
			continue
		}
		seen[title] = true
		out = append(out, mk("DS-RAT-IMG-004", engine.SeverityMedium, ref,
			title, desc,
			"Tag and deploy images by immutable version, ideally pinning the digest (name@sha256:...) so the running content is verifiable.",
			"CIS-DI-0005", "CIS-DI-0006"))
	}
	return out
}

// refTag extracts the tag from a "name:tag" reference, or "" if untagged. A
// colon that is part of a "registry:port" host (the segment after it contains a
// slash) is not a tag separator.
func refTag(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i+1:], "/") {
		return ref[i+1:]
	}
	return ""
}

// --- DS-RAT-IMG-006: exposed ports -----------------------------------------------

// rulePorts flags exposed privileged ports (<1024) and, most sharply, an
// exposed SSH port — a container that ships sshd is an anti-pattern and a
// lateral-movement foothold. Domain 10 (network exposure).
func rulePorts(ac *auditContext) []engine.Finding {
	var out []engine.Finding
	for _, spec := range ac.cfg.Config.sortedPorts() {
		portStr, proto, _ := strings.Cut(spec, "/")
		if proto == "" {
			proto = "tcp"
		}
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil {
			continue
		}
		switch {
		case port == 22:
			out = append(out, mk("DS-RAT-IMG-006", engine.SeverityHigh, spec,
				"SSH port exposed by image",
				"The image exposes port 22 (SSH). Containers should be immutable and accessed via the orchestrator; a built-in sshd is a lateral-movement foothold and an unmanaged credential surface.",
				"Remove sshd from the image and drop the EXPOSE 22; use `kubectl exec`/`docker exec` for debugging instead.",
				"MITRE-ATT&CK-T1021.004"))
		case port < 1024:
			out = append(out, mk("DS-RAT-IMG-006", engine.SeverityLow, spec,
				fmt.Sprintf("Privileged port %d/%s exposed", port, proto),
				fmt.Sprintf("The image exposes privileged port %d/%s (<1024). Binding it historically required root; prefer a high, unprivileged port and map it externally.", port, proto),
				"Expose an unprivileged port (>=1024) inside the container and remap it at the host/orchestrator layer.",
				"NIST-SP-800-190"))
		}
	}
	return out
}

// --- DS-RAT-IMG-007: sensitive volumes -------------------------------------------

// sensitiveVolumes are mount points that, when declared as VOLUMEs, invite a
// host-sensitive bind at run time (kernel/pseudo filesystems, the Docker
// socket, host root). Declaring them normalizes a dangerous run configuration.
var sensitiveVolumes = map[string]string{
	"/":                    "the host root filesystem",
	"/proc":                "the kernel process filesystem",
	"/sys":                 "the kernel sysfs",
	"/dev":                 "host devices",
	"/var/run/docker.sock": "the Docker daemon socket (equivalent to host root)",
	"/run/docker.sock":     "the Docker daemon socket (equivalent to host root)",
	"/var/run":             "host runtime sockets",
	"/etc":                 "host configuration",
	"/root":                "the host root user's home",
	"/var/lib/docker":      "the Docker daemon's state",
}

// ruleVolumes flags declared VOLUMEs over sensitive host paths. Domain 10.
func ruleVolumes(ac *auditContext) []engine.Finding {
	var out []engine.Finding
	for _, v := range ac.cfg.Config.sortedVolumes() {
		clean := "/" + strings.Trim(v, "/")
		if v == "/" {
			clean = "/"
		}
		if why, bad := sensitiveVolumes[clean]; bad {
			out = append(out, mk("DS-RAT-IMG-007", engine.SeverityHigh, clean,
				"Sensitive host path declared as VOLUME ("+clean+")",
				"The image declares a VOLUME at "+clean+", "+why+". Persisting this as a mount point steers operators toward binding host-sensitive state into the container.",
				"Remove the VOLUME declaration for "+clean+"; never mount host kernel/pseudo filesystems or the Docker socket into a container.",
				"NIST-SP-800-190", "MITRE-ATT&CK-T1610"))
		}
	}
	return out
}

// --- DS-RAT-IMG-008: provenance labels -------------------------------------------

// provenanceLabels are the OCI annotation keys that let a consumer trace an
// image back to its source, version, and license — the minimum for supply-chain
// accountability.
var provenanceLabels = []string{
	"org.opencontainers.image.source",
	"org.opencontainers.image.version",
	"org.opencontainers.image.licenses",
	"org.opencontainers.image.authors",
}

// ruleProvenanceLabels flags missing provenance metadata. It is LOW when no
// provenance labels exist at all and INFO when some are present but the set is
// incomplete, so a well-labeled image stays quiet.
func ruleProvenanceLabels(ac *auditContext) []engine.Finding {
	var missing []string
	present := 0
	for _, key := range provenanceLabels {
		if v, ok := ac.cfg.Config.Labels[key]; ok && strings.TrimSpace(v) != "" {
			present++
		} else {
			missing = append(missing, key)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	sev := engine.SeverityInfo
	if present == 0 {
		sev = engine.SeverityLow
	}
	return []engine.Finding{mk("DS-RAT-IMG-008", sev, ac.name,
		"Incomplete image provenance labels",
		"The image is missing OCI provenance annotations ("+strings.Join(missing, ", ")+"). Without them a consumer cannot trace the running image to its source, version, and license.",
		"Set the standard org.opencontainers.image.* labels (source, version, licenses, authors) at build time.",
		"https://github.com/opencontainers/image-spec/blob/main/annotations.md")}
}

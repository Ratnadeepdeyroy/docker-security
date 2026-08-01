package dockerbench

import (
	"fmt"
	"strconv"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
)

// --- Section 3: Docker daemon configuration files --------------------------
//
// These controls assess ownership and permissions of security-relevant files.
// The evidence carries a stat per path; when a path was not collected the
// control degrades to INFO. "More restrictive" is evaluated as a bitmask subset
// so 0600 correctly passes a "≤ 0644" requirement.

func fileControls() []compliance.Control {
	return []compliance.Control{
		{
			ID: "3.5", Title: "Ensure that the /etc/docker directory ownership is set to root:root",
			Section: secFiles, Level: compliance.Level1, Scored: true,
			Description: "Non-root ownership of /etc/docker lets an unprivileged user tamper with daemon configuration.",
			Remediation: "chown root:root /etc/docker",
			Fix:         &compliance.Fix{Kind: "file-perm", Target: "/etc/docker", Snippet: "chown root:root /etc/docker", DryRun: "set /etc/docker owner to root:root"},
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.3"), nist53("AC-6"), stig("SRG-APP-000516")},
		},
		{
			ID: "3.6", Title: "Ensure that the /etc/docker directory permissions are set to 755 or more restrictive",
			Section: secFiles, Level: compliance.Level1, Scored: true,
			Description: "World-writable configuration directories allow tampering with daemon settings.",
			Remediation: "chmod 755 /etc/docker",
			Fix:         &compliance.Fix{Kind: "file-perm", Target: "/etc/docker", Snippet: "chmod 755 /etc/docker", DryRun: "restrict /etc/docker to 0755"},
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.3"), nist53("CM-6"), stig("SRG-APP-000516")},
		},
		{
			ID: "3.15", Title: "Ensure that the Docker socket file ownership is set to root:docker",
			Section: secFiles, Level: compliance.Level1, Scored: true,
			Description: "The Docker socket is root-equivalent; incorrect ownership widens who can drive the daemon.",
			Remediation: "chown root:docker /var/run/docker.sock",
			Fix:         &compliance.Fix{Kind: "file-perm", Target: "/var/run/docker.sock", Snippet: "chown root:docker /var/run/docker.sock", DryRun: "set docker.sock owner to root:docker"},
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.3"), nist53("AC-6"), stig("SRG-APP-000033")},
		},
		{
			ID: "3.16", Title: "Ensure that the Docker socket file permissions are set to 660 or more restrictive",
			Section: secFiles, Level: compliance.Level1, Scored: true,
			Description: "A world-accessible Docker socket hands root-equivalent control to any local user.",
			Remediation: "chmod 660 /var/run/docker.sock",
			Fix:         &compliance.Fix{Kind: "file-perm", Target: "/var/run/docker.sock", Snippet: "chmod 660 /var/run/docker.sock", DryRun: "restrict docker.sock to 0660"},
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.3"), nist53("AC-6"), stig("SRG-APP-000033")},
		},
		{
			ID: "3.17", Title: "Ensure that the daemon.json file ownership is set to root:root",
			Section: secFiles, Level: compliance.Level1, Scored: true,
			Description: "daemon.json controls the daemon's security posture; only root should own it.",
			Remediation: "chown root:root /etc/docker/daemon.json",
			Fix:         &compliance.Fix{Kind: "file-perm", Target: "/etc/docker/daemon.json", Snippet: "chown root:root /etc/docker/daemon.json", DryRun: "set daemon.json owner to root:root"},
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.3"), nist53("AC-6"), stig("SRG-APP-000516")},
		},
		{
			ID: "3.18", Title: "Ensure that the daemon.json file permissions are set to 644 or more restrictive",
			Section: secFiles, Level: compliance.Level1, Scored: true,
			Description: "Overly permissive daemon.json permissions allow unprivileged tampering with daemon settings.",
			Remediation: "chmod 644 /etc/docker/daemon.json",
			Fix:         &compliance.Fix{Kind: "file-perm", Target: "/etc/docker/daemon.json", Snippet: "chmod 644 /etc/docker/daemon.json", DryRun: "restrict daemon.json to 0644"},
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.3"), nist53("CM-6"), stig("SRG-APP-000516")},
		},
	}
}

// checkOwnership assesses a file's owner:group against the expected pair.
func checkOwnership(e *Evidence, path, wantOwner, wantGroup string) compliance.Assessment {
	fs, ok := e.file(path)
	if !ok {
		return info(fmt.Sprintf("ownership of %s not collected", path))
	}
	if !fs.Exists {
		return info(fmt.Sprintf("%s does not exist on this host", path))
	}
	if fs.Owner == wantOwner && fs.Group == wantGroup {
		return pass(fmt.Sprintf("%s owned by %s:%s", path, fs.Owner, fs.Group))
	}
	return fail(fmt.Sprintf("%s should be owned by %s:%s", path, wantOwner, wantGroup),
		fmt.Sprintf("%s:%s", fs.Owner, fs.Group))
}

// checkPermsAtMost assesses that a file's mode carries no bits outside maxMode
// (i.e. it is maxMode "or more restrictive").
func checkPermsAtMost(e *Evidence, path string, maxMode uint32) compliance.Assessment {
	fs, ok := e.file(path)
	if !ok {
		return info(fmt.Sprintf("permissions of %s not collected", path))
	}
	if !fs.Exists {
		return info(fmt.Sprintf("%s does not exist on this host", path))
	}
	mode, err := parseMode(fs.Mode)
	if err != nil {
		return info(fmt.Sprintf("unparseable mode %q for %s", fs.Mode, path))
	}
	if mode&^maxMode == 0 {
		return pass(fmt.Sprintf("%s permissions %04o within %04o", path, mode, maxMode))
	}
	return fail(fmt.Sprintf("%s permissions %04o are looser than %04o", path, mode, maxMode),
		fmt.Sprintf("%04o", mode))
}

// parseMode parses an octal file mode string ("0644", "644", "0o644") into its
// permission bits, keeping only the low 12 bits (perms + setuid/setgid/sticky).
func parseMode(s string) (uint32, error) {
	s = trimModePrefix(s)
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n) & 0o7777, nil
}

func trimModePrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'o' || s[1] == 'O') {
		return s[2:]
	}
	return s
}

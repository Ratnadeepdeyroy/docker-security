//go:build linux

package runtime

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

// NewEnforcingResponder builds the Linux platform responder: kill sends
// SIGKILL directly via syscall; quarantine pauses the container and then
// best-effort disconnects it from the bridge network, both via the `docker`
// CLI with an arg vector (never a shell string).
func NewEnforcingResponder(p ResponsePolicy) *EnforcingResponder {
	return &EnforcingResponder{
		Policy:   p,
		Recorder: &RecordingResponder{},
		kill: func(pid int) error {
			if pid <= 0 {
				return fmt.Errorf("enforce: refusing to signal invalid pid %d", pid)
			}
			return syscall.Kill(pid, syscall.SIGKILL)
		},
		pause:   func(id string) error { return dockerAction("pause", id) },
		isolate: func(id string) error { return dockerNetworkDisconnect(id) },
	}
}

// enforceIDRe is the safe charset for a container name/ID passed to docker by
// the enforcing responder. It must not begin with '-' (would be read as a
// flag). Named distinctly from the package's other containerIDRe (which
// matches 64-hex cgroup ids for attribution) to avoid colliding with it.
var enforceIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// validContainerID reports whether id is safe to pass to the docker CLI.
func validContainerID(id string) bool { return enforceIDRe.MatchString(id) }

// dockerAction runs `docker <verb> <id>` after validating id's charset and
// confirming a docker binary is present. Arguments are always passed as a
// vector, never through a shell.
func dockerAction(verb, id string) error {
	if !validContainerID(id) {
		return fmt.Errorf("enforce: refusing unsafe container id %q", id)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("enforce: docker binary not found: %w", err)
	}
	cmd := exec.Command("docker", verb, id)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("docker %s %s: %s", verb, id, msg)
	}
	return nil
}

// dockerNetworkDisconnect best-effort isolates a container from the default
// bridge network. It is intentionally forgiving of the network name (a fixed,
// non-attacker-controlled literal) and only validates the attacker-influenced
// container id.
func dockerNetworkDisconnect(id string) error {
	if !validContainerID(id) {
		return fmt.Errorf("enforce: refusing unsafe container id %q", id)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("enforce: docker binary not found: %w", err)
	}
	cmd := exec.Command("docker", "network", "disconnect", "bridge", id)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("docker network disconnect bridge %s: %s", id, msg)
	}
	return nil
}

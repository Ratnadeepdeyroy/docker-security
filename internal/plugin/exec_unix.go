//go:build unix

package plugin

import (
	"os/exec"
	"syscall"
)

// isolateProcess puts the plugin in its own process group and, on cancellation,
// kills the whole group. This matters for the timeout to be real: if we killed
// only the direct child, a grandchild it spawned (e.g. a `sleep` in a wrapper
// script) would keep our stdout pipe open and Wait would block until that
// grandchild exited — so a hung plugin would stall the scan for its full
// runtime, not the timeout. Killing the group closes the pipe immediately and
// Wait returns at the deadline.
func isolateProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid targets the process group led by the child.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

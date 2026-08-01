//go:build !unix

package plugin

import "os/exec"

// isolateProcess is a no-op on non-unix platforms; the context deadline still
// terminates the direct child.
func isolateProcess(_ *exec.Cmd) {}

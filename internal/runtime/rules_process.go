package runtime

import (
	"path"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file holds the process/execution rules: a service spawning a shell,
// binaries that never shipped in the image (drift), crypto-miners, and reverse
// shells. These are the workhorse detections — most container attacks show up
// first as an unexpected process.

// --- DS-RAT-RT-001 shell-in-container ----------------------------------------

type shellRule struct{ ruleBase }

func newShellRule() Rule {
	return &shellRule{ruleBase{
		id: "DS-RAT-RT-001",
		info: RuleInfo{
			Title:       "Interactive shell spawned in container",
			Severity:    engine.SeverityHigh,
			Technique:   techUnixShell,
			Default:     true,
			Description: "A shell was executed inside a running container. Service containers rarely need a shell at runtime; it is the most common post-exploitation pivot.",
			Remediation: "Investigate the parent process and session. Use distroless/no-shell images, and restrict `exec` into production pods via RBAC. If unexpected, isolate the container and rotate any credentials it could reach.",
		},
	}}
}

func (r *shellRule) Evaluate(ev *Event, st *State) []Detection {
	if ev.Kind != KindProcess || !isShell(ev.Process.Exe, ev.Process.Comm) {
		return nil
	}
	// The entrypoint itself may legitimately be a shell (many images use
	// `sh -c`). Fire when a *non-shell* service ancestor spawned the shell, i.e.
	// the shell is not the container's own PID 1 lineage.
	if shellIsEntrypoint(ev.Process.Ancestry) {
		return nil
	}
	parent := ""
	if n := len(ev.Process.Ancestry); n >= 2 {
		parent = ev.Process.Ancestry[n-2]
	}
	meta := map[string]string{
		"shell":    path.Base(ev.Process.Exe),
		"parent":   parent,
		"tty":      boolStr(ev.Process.TTY),
		"ancestry": strings.Join(ev.Process.Ancestry, " -> "),
	}
	msg := "shell " + ev.Process.Exe + " (pid " + itoa(ev.Process.PID) + ")"
	if parent != "" {
		msg += " spawned by " + parent
	}
	if ev.Process.TTY {
		msg += " with an attached tty (interactive)"
	}
	return []Detection{r.fire(ev, msg, meta)}
}

// shellIsEntrypoint reports whether the shell is the container's own entrypoint
// lineage (ancestry is all shells / very short), which is benign.
func shellIsEntrypoint(ancestry []string) bool {
	if len(ancestry) == 0 {
		return false // no lineage info: treat as suspicious, do not suppress
	}
	for _, a := range ancestry {
		if !isShell(a, path.Base(a)) && !isInitLike(a) {
			return false
		}
	}
	return true
}

// isInitLike matches container init/pause processes that legitimately head a
// shell-based entrypoint.
func isInitLike(exe string) bool {
	switch path.Base(exe) {
	case "pause", "tini", "dumb-init", "init", "docker-init", "s6-svscan":
		return true
	}
	return false
}

// --- DS-RAT-RT-002 drift: non-image binary executed --------------------------

type driftRule struct{ ruleBase }

func newDriftRule() Rule {
	return &driftRule{ruleBase{
		id: "DS-RAT-RT-002",
		info: RuleInfo{
			Title:       "Binary not present in image executed (drift)",
			Severity:    engine.SeverityHigh,
			Technique:   techIngressTool,
			Default:     true,
			Description: "A process executed an executable that did not ship in the container image, indicating a dropped tool or downloaded payload — a strong sign of active compromise.",
			Remediation: "Treat the container as compromised: capture forensics, isolate it, and redeploy from a trusted image. Enforce a read-only root filesystem and drop write access to executable paths.",
		},
	}}
}

func (r *driftRule) Evaluate(ev *Event, st *State) []Detection {
	if ev.Kind != KindProcess || ev.Process.Exe == "" {
		return nil
	}
	inv, ok := st.imageInventory(ev.Container)
	if !ok {
		return nil // no inventory → cannot judge drift; stay silent (no false alarms)
	}
	if _, shipped := inv[ev.Process.Exe]; shipped {
		return nil
	}
	// Fire once per novel drifted binary per container to avoid alert storms.
	if !st.markExec(containerKey(ev.Container)+"|drift", ev.Process.Exe) {
		return nil
	}
	meta := map[string]string{
		"drifted_binary": ev.Process.Exe,
		"image":          ev.Container.ImageRef,
	}
	msg := "executable " + ev.Process.Exe + " (pid " + itoa(ev.Process.PID) + ") is not part of image " + ev.Container.ImageRef
	return []Detection{r.fire(ev, msg, meta)}
}

// --- DS-RAT-RT-006 crypto-mining ---------------------------------------------

type cryptoMiningRule struct{ ruleBase }

func newCryptoMiningRule() Rule {
	return &cryptoMiningRule{ruleBase{
		id: "DS-RAT-RT-006",
		info: RuleInfo{
			Title:       "Crypto-mining activity detected",
			Severity:    engine.SeverityHigh,
			Technique:   techResourceHijack,
			Default:     true,
			Description: "A process matched crypto-miner signatures by binary name or command-line arguments (e.g. a stratum pool URL). Cryptojacking is the most common outcome of an exposed container.",
			Remediation: "Kill the process and isolate the workload. Investigate the initial-access vector (exposed service, leaked credentials). Apply CPU limits and egress controls to pools.",
		},
	}}
}

func (r *cryptoMiningRule) Evaluate(ev *Event, st *State) []Detection {
	if ev.Kind != KindProcess {
		return nil
	}
	reason, ok := looksLikeMiner(ev.Process.Exe, ev.Process.Comm, ev.Process.Args)
	if !ok {
		return nil
	}
	meta := map[string]string{"signal": reason, "exe": ev.Process.Exe}
	return []Detection{r.fire(ev, "crypto-miner indicator: "+reason+" (pid "+itoa(ev.Process.PID)+")", meta)}
}

// --- DS-RAT-RT-010 reverse shell ---------------------------------------------

type reverseShellRule struct{ ruleBase }

func newReverseShellRule() Rule {
	return &reverseShellRule{ruleBase{
		id: "DS-RAT-RT-010",
		info: RuleInfo{
			Title:       "Reverse/bind shell detected",
			Severity:    engine.SeverityCritical,
			Technique:   techAppLayerC2,
			Default:     true,
			Description: "A shell process has its standard I/O bound to a network socket, or was launched with an interpreter reverse-shell one-liner. This is hands-on-keyboard remote control of the container.",
			Remediation: "Isolate the container immediately and capture a forensic bundle. Identify the remote endpoint and block it. Rotate all credentials reachable from the workload.",
		},
	}}
}

func (r *reverseShellRule) Evaluate(ev *Event, st *State) []Detection {
	if ev.Kind != KindProcess {
		return nil
	}
	// Signal 1: a shell with stdio wired to a socket.
	if ev.Process.StdioSocket && isShell(ev.Process.Exe, ev.Process.Comm) {
		meta := map[string]string{"exe": ev.Process.Exe, "signal": "shell stdio bound to socket"}
		return []Detection{r.fire(ev, "reverse shell: "+ev.Process.Exe+" (pid "+itoa(ev.Process.PID)+") has socket-backed stdio", meta)}
	}
	// Signal 2: an interpreter invoked with a classic reverse-shell payload.
	if sig, ok := reverseShellPayload(ev.Process.Args); ok {
		meta := map[string]string{"exe": ev.Process.Exe, "signal": sig}
		return []Detection{r.fire(ev, "reverse shell payload in args: "+sig+" (pid "+itoa(ev.Process.PID)+")", meta)}
	}
	return nil
}

// reverseShellPayload spots well-known reverse-shell one-liners in argv.
func reverseShellPayload(args []string) (string, bool) {
	joined := strings.ToLower(strings.Join(args, " "))
	for _, sig := range []string{
		"/dev/tcp/", "/dev/udp/",
		"socket.socket", "sh -i", "bash -i",
		"os.dup2", "pty.spawn", "fsockopen", "socat exec",
	} {
		if strings.Contains(joined, sig) {
			return sig, true
		}
	}
	return "", false
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

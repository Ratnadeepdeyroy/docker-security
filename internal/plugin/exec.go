package plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// maxOutput caps how much a plugin may write to stdout. A plugin that floods
// stdout is truncated and treated as an error, so it cannot exhaust host memory.
const maxOutput = 16 << 20 // 16 MiB

// maxContent caps how much target content we base64 into the request, so a huge
// target does not blow up the plugin's stdin (and the plugin's own memory).
const maxContent = 8 << 20 // 8 MiB

// --- Request/response codecs ---------------------------------------------

func toWireTarget(t *engine.Target) wireTarget {
	wt := wireTarget{Type: string(t.Type), Location: t.Location, Metadata: t.Metadata}
	if len(t.Content) > 0 {
		content := t.Content
		if len(content) > maxContent {
			content = content[:maxContent]
		}
		wt.ContentBase64 = base64.StdEncoding.EncodeToString(content)
	}
	return wt
}

func marshalRequest(req pluginRequest) ([]byte, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func parseResponse(out []byte) (*pluginResponse, error) {
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("plugin produced no output")
	}
	var resp pluginResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("decode plugin output: %w", err)
	}
	return &resp, nil
}

// --- execRunner: the real, sandboxed subprocess runner -------------------

// execRunner launches the plugin as an isolated child process.
type execRunner struct{}

// run executes argv with stdin, bounded by a timeout and an output cap. It uses
// no shell (argv is passed directly), a scrubbed environment (so the plugin does
// not inherit host secrets), and its own process group so a timeout kill reaps
// any children the plugin spawned.
func (execRunner) run(ctx context.Context, argv []string, timeoutMS int, stdin []byte) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty exec argv")
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	// Minimal environment: PATH only. Plugins declare their own needs; they do
	// not get the host's secrets, tokens, or registry credentials.
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin"}
	// WaitDelay bounds how long Wait blocks after cancellation before force-closing
	// the plugin's I/O pipes. It is the portable backstop that guarantees Analyze
	// returns near the deadline even where group-kill is unavailable.
	cmd.WaitDelay = 2 * time.Second
	isolateProcess(cmd) // own process group + group-kill on cancel (see exec_unix.go)

	var stdout, stderr bytes.Buffer
	// LimitReader on the writer side: cap stdout so a runaway plugin cannot fill memory.
	cmd.Stdout = &limitedWriter{w: &stdout, remaining: maxOutput}
	cmd.Stderr = &limitedWriter{w: &stderr, remaining: 64 << 10}

	err := cmd.Run()
	if runCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("timed out after %dms", timeoutMS)
	}
	if err != nil {
		msg := stderr.String()
		if msg != "" {
			return nil, fmt.Errorf("exec failed: %v: %s", err, msg)
		}
		return nil, fmt.Errorf("exec failed: %w", err)
	}
	return stdout.Bytes(), nil
}

// limitedWriter buffers up to a byte budget and silently drops the rest, so a
// plugin that streams unbounded output cannot grow host memory without bound. It
// always reports the full write as accepted so the child is not killed by a
// broken pipe mid-write — we simply keep only the first maxOutput bytes, which a
// well-formed single-JSON response never exceeds.
type limitedWriter struct {
	w         io.Writer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining > 0 {
		keep := p
		if len(keep) > l.remaining {
			keep = keep[:l.remaining]
		}
		if _, err := l.w.Write(keep); err != nil {
			return 0, err
		}
		l.remaining -= len(keep)
	}
	return len(p), nil
}

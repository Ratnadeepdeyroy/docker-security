package mcp

import (
	"bufio"
	"context"
	"io"
	"net/http"
)

// --- Transports ----------------------------------------------------------
//
// MCP is transport-agnostic JSON-RPC. We offer two: newline-delimited messages
// over stdio (how a local agent host launches and talks to a tool server) and a
// single-shot HTTP endpoint (how a networked agent reaches it). Both funnel into
// the same handleMessage, so tool behaviour is identical regardless of transport.

// maxLine bounds a single stdio message so a hostile or runaway client cannot
// drive unbounded allocation. 8 MiB comfortably fits a large Dockerfile scan.
const maxLine = 8 << 20

// maxHTTPBody bounds an HTTP request body for the same reason.
const maxHTTPBody = 8 << 20

// ServeStdio runs the server over a newline-delimited JSON-RPC stream until in
// is exhausted or ctx is cancelled. Each inbound line is one request; each
// response is written as one line. Notifications produce no output.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	w := bufio.NewWriter(out)
	defer w.Flush()

	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		resp, err := s.handleMessage(ctx, line)
		if err != nil {
			return err
		}
		if resp == nil {
			continue // notification
		}
		if _, err := w.Write(resp); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return sc.Err()
}

// HTTPHandler returns an http.Handler that accepts one JSON-RPC request per POST
// and returns its response. The master can mount this at /mcp on the existing
// server mux. A notification (no id) yields 204 No Content.
func (s *Server) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed (POST a JSON-RPC request)", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := s.handleMessage(r.Context(), body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if resp == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	})
}

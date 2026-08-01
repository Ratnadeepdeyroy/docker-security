package authz

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

// Command dispatches `dsecrat authz <serve>`.
func Command(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: dsecrat authz serve [flags]")
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "authz: unknown subcommand %q (want serve)\n", args[0])
		return 2
	}
}

// serve runs the Docker authorization-plugin HTTP server.
//
//	dockerd --authorization-plugin=<name>  # points at the socket this serves
func serve(args []string) int {
	fs := flag.NewFlagSet("authz serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:880", "listen address (or use --socket for a unix socket)")
	socket := fs.String("socket", "", "unix socket path to listen on (Docker plugin convention: /run/docker/plugins/<name>.sock)")
	denyPrivileged := fs.Bool("deny-privileged", true, "deny privileged container creation")
	denyHostNS := fs.Bool("deny-host-namespaces", true, "deny host PID/IPC/network/UTS namespace sharing")
	denyHostPath := fs.Bool("deny-host-path-mounts", true, "deny bind-mounting sensitive host paths")
	denySocket := fs.Bool("deny-docker-socket", true, "deny mounting the Docker daemon socket into a container")
	readOnly := fs.Bool("read-only", false, "deny all mutating (POST/PUT/DELETE) Docker API calls")
	denyCaps := fs.String("deny-cap-add", "SYS_ADMIN,NET_ADMIN,SYS_MODULE,SYS_PTRACE,DAC_READ_SEARCH,BPF", "comma-separated capabilities to deny adding")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	pol := &Policy{
		DenyPrivileged:        *denyPrivileged,
		DenyHostNamespaces:    *denyHostNS,
		DenyHostPathMounts:    *denyHostPath,
		DenyDockerSocketMount: *denySocket,
		ReadOnly:              *readOnly,
		DenyCapAdd:            splitCSV(*denyCaps),
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := NewServer(pol, log)

	var ln net.Listener
	var err error
	if *socket != "" {
		_ = os.Remove(*socket) // stale socket from a prior run
		ln, err = net.Listen("unix", *socket)
		fmt.Fprintf(os.Stderr, "dsecrat authz plugin listening on unix://%s\n", *socket)
	} else {
		ln, err = net.Listen("tcp", *addr)
		fmt.Fprintf(os.Stderr, "dsecrat authz plugin listening on http://%s\n", *addr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "authz serve:", err)
		return 1
	}
	defer ln.Close()

	if err := http.Serve(ln, srv); err != nil {
		fmt.Fprintln(os.Stderr, "authz serve:", err)
		return 1
	}
	return 0
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

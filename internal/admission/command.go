package admission

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

// --- `dsecrat admission serve` command ----------------------------------------
//
// The exported command body the master wires into cli.go (see NOTES.md). It
// compiles the policy once at startup — a policy that does not compile is a
// configuration error the operator must see before the webhook ever admits a
// pod — then serves until killed.

// Command dispatches `dsecrat admission <serve> ...`.
func Command(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "serve":
		return ServeCommand(args[1:])
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "admission: unknown subcommand %q\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: dsecrat admission serve [flags]

Run the ValidatingWebhook server. Register it in Kubernetes with
failurePolicy: Fail and a short timeoutSeconds for cluster-side fail-closed.

Flags:
`)
	serveFlags(flag.NewFlagSet("admission serve", flag.ContinueOnError)).PrintDefaults()
}

// serveFlags declares the serve flag set (shared by usage and ServeCommand).
func serveFlags(fs *flag.FlagSet) *flag.FlagSet {
	fs.String("policy", "", "path to the policy JSON (required)")
	fs.String("addr", ":8443", "listen address")
	fs.String("tls-cert", "", "TLS certificate PEM (required for real clusters)")
	fs.String("tls-key", "", "TLS private key PEM")
	fs.Bool("explain", false, "attach agent-consumable explanations to responses (off by default)")
	fs.Bool("fail-open", false, "admit on internal evaluation error instead of denying (audit rollouts only)")
	return fs
}

// ServeCommand implements `dsecrat admission serve`.
func ServeCommand(args []string) int {
	fs := serveFlags(flag.NewFlagSet("admission serve", flag.ContinueOnError))
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	policyPath := fs.Lookup("policy").Value.String()
	addr := fs.Lookup("addr").Value.String()
	tlsCert := fs.Lookup("tls-cert").Value.String()
	tlsKey := fs.Lookup("tls-key").Value.String()
	explain := fs.Lookup("explain").Value.String() == "true"
	failOpen := fs.Lookup("fail-open").Value.String() == "true"

	if policyPath == "" {
		fmt.Fprintln(os.Stderr, "admission serve: --policy is required")
		return 2
	}

	eng, err := compilePolicyFile(policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admission serve:", err)
		return 1
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rv := NewReviewer(eng,
		WithClock(func() time.Time { return time.Now().UTC() }),
		WithExplain(explain),
		WithFailOpen(failOpen),
	)
	srv := NewServer(rv, log)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
	}

	mode := "fail-closed"
	if failOpen {
		mode = "fail-open"
	}
	fmt.Fprintf(os.Stderr, "admission serve: policy %q loaded; listening on %s (%s)\n",
		eng.Policy().Name, addr, mode)

	if tlsCert != "" && tlsKey != "" {
		if err := httpServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			fmt.Fprintln(os.Stderr, "admission serve:", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "admission serve: WARNING serving plaintext HTTP; provide --tls-cert/--tls-key for production")
	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "admission serve:", err)
		return 1
	}
	return 0
}

// compilePolicyFile reads and compiles a policy document.
func compilePolicyFile(path string) (*policy.Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	eng, err := policy.CompileBytes(data)
	if err != nil {
		return nil, err
	}
	return eng, nil
}

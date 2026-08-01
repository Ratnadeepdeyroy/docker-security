package mcp

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/store"
)

// Command implements `dsecrat mcp`: start the MCP server so an AI agent can drive
// the engine. It defaults to stdio (how agent hosts launch tool servers) and can
// serve HTTP with --http. It takes the module registry from the caller so this
// package never imports the module aggregator — the master wires it (see
// NOTES.md):
//
//	case "mcp":
//	    return mcp.Command(modules.Default(), rest)
func Command(reg *engine.Registry, args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	httpAddr := fs.String("http", "", "serve MCP over HTTP on this address (e.g. :7423) instead of stdio")
	storeDir := fs.String("store", "", "enable the scan store at this directory (needed for get_findings/query_inventory)")
	allowMut := fs.Bool("allow-mutations", false, "allow mutating tools (scan persistence); off by default")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat mcp [--http addr] [--store dir] [--allow-mutations]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var opts []Option
	opts = append(opts, WithMutations(*allowMut))
	if *storeDir != "" {
		st, err := store.Open(*storeDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mcp:", err)
			return 1
		}
		opts = append(opts, WithStore(st))
	}
	srv := New(reg, opts...)

	if *httpAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/mcp", srv.HTTPHandler())
		fmt.Fprintf(os.Stderr, "docker-security MCP server on http://%s/mcp (mutations=%v)\n", *httpAddr, *allowMut)
		if err := http.ListenAndServe(*httpAddr, mux); err != nil {
			fmt.Fprintln(os.Stderr, "mcp:", err)
			return 1
		}
		return 0
	}

	// stdio: the default agent-host transport.
	if err := srv.ServeStdio(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		return 1
	}
	return 0
}

package plugin

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// Command implements `dsecrat plugins`: discover and inspect out-of-process
// plugins. It does not need the engine registry (it reports on the plugins
// themselves), so its signature is the standard Command(args). The master wires
// it as (see NOTES.md):
//
//	case "plugins":
//	    return plugin.Command(rest)
//
// Subcommands: list (default) prints discovered plugins; validate exits non-zero
// if any manifest in the directory is invalid.
func Command(args []string) int {
	fs := flag.NewFlagSet("plugins", flag.ContinueOnError)
	dir := fs.String("dir", "plugins", "directory of plugin manifests (*.json)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat plugins [--dir DIR] [list|validate]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sub := "list"
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}

	h, loadErr := LoadDir(*dir)
	switch sub {
	case "list":
		printPlugins(os.Stdout, h)
		if loadErr != nil {
			fmt.Fprintln(os.Stderr, "warning:", loadErr)
		}
		return 0
	case "validate":
		printPlugins(os.Stdout, h)
		if loadErr != nil {
			fmt.Fprintln(os.Stderr, "invalid:", loadErr)
			return 1
		}
		fmt.Fprintf(os.Stdout, "\nall %d manifest(s) valid\n", len(h.Plugins()))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q (want: list, validate)\n", sub)
		return 2
	}
}

func printPlugins(w *os.File, h *Host) {
	plugins := h.Plugins()
	if len(plugins) == 0 {
		fmt.Fprintln(w, "no plugins found")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVERSION\tTARGETS\tDOMAINS\tDESCRIPTION")
	for _, p := range plugins {
		m := p.Manifest()
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			m.Name, orDash(m.Version), joinOrDash(m.TargetTypes), joinOrDash(m.Domains), m.Description)
	}
	tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinOrDash(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return strings.Join(ss, ",")
}

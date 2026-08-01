package secrets

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Ratnadeepdeyroy/docker-security/internal/secrets"
)

// Command implements the `dsecrat secrets` subcommand surface. Today it exposes
// honeytoken generation — decoy credentials to plant in images or repos so any
// later *use* of them is a high-confidence intrusion signal. The master wires
// this into cli.go (see NOTES.md); the body lives here to keep the CLI file
// out of this phase's lane.
//
// Usage:
//
//	dsecrat secrets honeytoken --label <name> [--count N]
//
// Output is a decoy value plus its fingerprint. The value is intentionally
// printable: it is not a real secret, it is a tripwire you embed on purpose.
func Command(args []string) int {
	return command(args, os.Stdout, os.Stderr)
}

// command is the testable core of Command with injectable output streams.
func command(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: dsecrat secrets <honeytoken> [flags]")
		return 2
	}
	switch args[0] {
	case "honeytoken":
		return honeytokenCmd(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "secrets: unknown subcommand %q (want: honeytoken)\n", args[0])
		return 2
	}
}

func honeytokenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("honeytoken", flag.ContinueOnError)
	fs.SetOutput(stderr)
	label := fs.String("label", "", "label identifying where this canary is planted (required)")
	count := fs.Int("count", 1, "number of distinct canaries to generate")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *label == "" || *count < 1 {
		fmt.Fprintln(stderr, "secrets honeytoken: --label is required and --count must be >= 1")
		return 2
	}
	for i := 0; i < *count; i++ {
		lbl := *label
		if *count > 1 {
			lbl = fmt.Sprintf("%s-%d", *label, i)
		}
		h := secrets.GenerateHoneytoken(lbl)
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", h.Label, h.Value, h.Fingerprint)
	}
	return 0
}

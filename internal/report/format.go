// Package report renders an engine.Report into human- and machine-readable
// formats. Formatters are the output-side adapters of the tool; they are the
// same regardless of whether the run came from the CLI, the HTTP API, or a
// connector.
package report

import (
	"fmt"
	"io"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// Formatter renders a report to a writer.
type Formatter interface {
	Format(w io.Writer, r *engine.Report) error
}

// Formats lists the supported format names.
func Formats() []string { return []string{"table", "json", "sarif"} }

// Get returns the formatter for a name. An empty name defaults to "table".
func Get(name string) (Formatter, error) {
	switch name {
	case "", "table":
		return Table{}, nil
	case "json":
		return JSON{}, nil
	case "sarif":
		return SARIF{}, nil
	default:
		return nil, fmt.Errorf("unknown format %q (want one of: table, json, sarif)", name)
	}
}

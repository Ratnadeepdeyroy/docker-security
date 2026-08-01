package report

import (
	"encoding/json"
	"io"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// JSON renders the full report as indented JSON.
type JSON struct{}

func (JSON) Format(w io.Writer, r *engine.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

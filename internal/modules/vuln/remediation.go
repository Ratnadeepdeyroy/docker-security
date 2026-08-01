package vuln

import (
	"encoding/json"

	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

// --- Agent-consumable remediation ---------------------------------------
//
// Each finding carries a structured fix an AI agent (or a bot) can turn into a
// concrete change — bump this package from a→b — without parsing prose. This is
// the machine half of the human Remediation string.

// Fix is a structured, model-consumable remediation.
type Fix struct {
	// Type is "upgrade" when a fixed version exists, else "no-fix".
	Type      string `json:"type"`
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	From      string `json:"from"`
	To        string `json:"to,omitempty"`
	// Action is a terse imperative an agent can act on directly.
	Action string `json:"action"`
}

func structuredFix(coord vulndb.Coord, fixed string) Fix {
	if fixed == "" {
		return Fix{
			Type:      "no-fix",
			Ecosystem: string(coord.Ecosystem),
			Package:   coord.Package,
			From:      coord.Version,
			Action:    "no fixed version available; monitor advisory or remove/replace the package",
		}
	}
	return Fix{
		Type:      "upgrade",
		Ecosystem: string(coord.Ecosystem),
		Package:   coord.Package,
		From:      coord.Version,
		To:        fixed,
		Action:    "upgrade " + coord.Package + " to " + fixed,
	}
}

// encodeFix serializes a Fix to compact JSON for the finding metadata. Map key
// order in encoding/json is stable (struct field order), keeping output
// deterministic.
func encodeFix(f Fix) string {
	data, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	return string(data)
}

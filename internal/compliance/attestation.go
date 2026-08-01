package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// AttestationRegister holds the waivers (for accepted Failed controls) and
// attestations (for manual/inherited controls). Both carry an owner and an
// expiry so accepted risk and manual evidence are auditable and time-bounded —
// never a permanent silent pass (COMPLIANCE_PLAN §4.4).
type AttestationRegister struct {
	Entries []RegisterEntry `json:"entries"`
}

// RegisterEntry is one waiver or attestation for a specific control.
type RegisterEntry struct {
	Kind          string    `json:"kind"` // "waiver" | "attestation"
	Framework     string    `json:"framework"`
	ControlID     string    `json:"control_id"`
	Owner         string    `json:"owner"`
	Justification string    `json:"justification,omitempty"` // waivers
	Evidence      string    `json:"evidence,omitempty"`      // attestations (policy link, SOC report)
	Expires       time.Time `json:"expires"`
}

// LoadRegister reads a JSON register from disk. A missing path yields an empty
// register (no waivers/attestations), not an error.
func LoadRegister(path string) (*AttestationRegister, error) {
	if path == "" {
		return &AttestationRegister{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &AttestationRegister{}, nil
		}
		return nil, fmt.Errorf("read register %q: %w", path, err)
	}
	var r AttestationRegister
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse register %q: %w", path, err)
	}
	return &r, nil
}

// Waiver returns a valid (unexpired) waiver for a control, if one exists.
func (r *AttestationRegister) Waiver(framework, id string, now time.Time) (RegisterEntry, bool) {
	return r.find("waiver", framework, id, now)
}

// Attestation returns a valid (unexpired) attestation for a control, if one exists.
func (r *AttestationRegister) Attestation(framework, id string, now time.Time) (RegisterEntry, bool) {
	return r.find("attestation", framework, id, now)
}

func (r *AttestationRegister) find(kind, framework, id string, now time.Time) (RegisterEntry, bool) {
	if r == nil {
		return RegisterEntry{}, false
	}
	for _, e := range r.Entries {
		if e.Kind != kind || e.Framework != framework || e.ControlID != id {
			continue
		}
		// An entry with no expiry is treated as expired: the plan requires a
		// bounded lifetime, so an unbounded entry must not silently pass.
		if e.Expires.IsZero() || !now.Before(e.Expires) {
			continue
		}
		return e, true
	}
	return RegisterEntry{}, false
}

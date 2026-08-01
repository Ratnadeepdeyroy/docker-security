package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Exception suppresses a specific detection an operator has vetted as benign.
// Matching is by rule id plus optional narrowing scope (image, container,
// path-prefix, arg-substring). Prefix/substring only — no regex — so an
// exception is auditable and cannot silently over-match.
type Exception struct {
	RuleID     string `json:"rule_id"`
	ImageRef   string `json:"image_ref,omitempty"`
	Container  string `json:"container,omitempty"`   // matches Name or ID
	PathPrefix string `json:"path_prefix,omitempty"` // matches Metadata["path"]
	ArgSubstr  string `json:"arg_substr,omitempty"`  // substring of joined Process.Args
	Note       string `json:"note,omitempty"`
}

// ExceptionSet is a loaded collection of operator-vetted exceptions.
type ExceptionSet struct {
	Rules []Exception `json:"exceptions"`
}

// exceptionsSizeLimit bounds how much untrusted exceptions JSON we will parse,
// mirroring the same defensive cap LoadScenario applies to recorded telemetry.
const exceptionsSizeLimit = 64 << 20 // 64 MiB

// LoadExceptions decodes an ExceptionSet from a JSON file, defending against
// oversized input and unknown fields so a malformed or hostile file fails
// loudly instead of silently under- or over-matching.
func LoadExceptions(path string) (*ExceptionSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open exceptions: %w", err)
	}
	defer f.Close()

	limited := io.LimitReader(f, exceptionsSizeLimit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read exceptions: %w", err)
	}
	if len(data) > exceptionsSizeLimit {
		return nil, fmt.Errorf("exceptions file exceeds %d byte limit", exceptionsSizeLimit)
	}
	var es ExceptionSet
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&es); err != nil {
		return nil, fmt.Errorf("decode exceptions: %w", err)
	}
	return &es, nil
}

// Suppressed reports whether d matches any exception. An exception matches when
// its RuleID equals d.RuleID AND every non-empty narrowing field also matches.
// Nil-safe: a nil set suppresses nothing.
func (e *ExceptionSet) Suppressed(d Detection) bool {
	if e == nil {
		return false
	}
	for _, ex := range e.Rules {
		if ex.matches(d) {
			return true
		}
	}
	return false
}

// matches reports whether a single Exception matches d.
func (ex Exception) matches(d Detection) bool {
	if ex.RuleID != d.RuleID {
		return false
	}
	if ex.ImageRef != "" && ex.ImageRef != d.Container.ImageRef {
		return false
	}
	if ex.Container != "" && ex.Container != d.Container.Name && ex.Container != d.Container.ID {
		return false
	}
	if ex.PathPrefix != "" && !strings.HasPrefix(d.Metadata["path"], ex.PathPrefix) {
		return false
	}
	if ex.ArgSubstr != "" && !strings.Contains(strings.Join(d.Process.Args, " "), ex.ArgSubstr) {
		return false
	}
	return true
}

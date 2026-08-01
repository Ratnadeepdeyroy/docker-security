package imageaudit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// --- Image config model ------------------------------------------------------
//
// The on-disk image config is the same JSON blob for both a `docker save`
// tarball and an OCI image layout: an OCI image-configuration object. The
// top-level keys are lower-case (created/architecture/os/config/history) while
// the runtime knobs inside "config" use Docker's historical capitalized keys
// (User, Env, ExposedPorts, ...). Docker's BuildKit adds a "Healthcheck" object
// that the base OCI spec omits; we parse it because HEALTHCHECK presence is a
// CIS control. We deliberately model only the fields the audit reasons about
// and let encoding/json ignore the rest, so a newer schema never breaks us.

// imageConfig is the parsed image-configuration document.
type imageConfig struct {
	Architecture string          `json:"architecture"`
	OS           string          `json:"os"`
	Config       containerConfig `json:"config"`
	History      []historyEntry  `json:"history"`
}

// containerConfig is the runtime configuration baked into the image.
type containerConfig struct {
	User         string            `json:"User"`
	ExposedPorts map[string]empty  `json:"ExposedPorts"`
	Env          []string          `json:"Env"`
	Entrypoint   []string          `json:"Entrypoint"`
	Cmd          []string          `json:"Cmd"`
	Volumes      map[string]empty  `json:"Volumes"`
	WorkingDir   string            `json:"WorkingDir"`
	Labels       map[string]string `json:"Labels"`
	StopSignal   string            `json:"StopSignal"`
	Healthcheck  *healthcheck      `json:"Healthcheck"`
}

// empty is the value type of the config's set-shaped fields (ExposedPorts,
// Volumes) whose JSON values are always the empty object {}.
type empty struct{}

// healthcheck mirrors the container HEALTHCHECK. Only Test tells us whether a
// real probe (vs. the inherited/NONE default) is configured, which is all the
// audit needs.
type healthcheck struct {
	Test []string `json:"Test"`
}

// historyEntry is one build-history record. created_by holds the instruction
// text (e.g. "RUN /bin/sh -c apt-get ...") that produced a layer, which is what
// we mine for dangerous build steps.
type historyEntry struct {
	CreatedBy  string `json:"created_by"`
	Comment    string `json:"comment"`
	EmptyLayer bool   `json:"empty_layer"`
}

// maxHistoryEntries bounds how many history records we inspect. A hostile image
// could ship millions of empty-layer entries; the meaningful build steps are
// always near the front, so we cap the scan rather than let it run unbounded.
const maxHistoryEntries = 4096

// parseConfig decodes an image-config JSON blob. An empty blob is valid (some
// images ship "{}"): it yields a zero config, which the rules read as "no USER,
// no healthcheck, no labels" — all legitimately reportable states. A blob that
// is present but malformed is an error the caller surfaces, never a panic.
func parseConfig(raw []byte) (*imageConfig, error) {
	cfg := &imageConfig{}
	if len(raw) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse image config: %w", err)
	}
	if len(cfg.History) > maxHistoryEntries {
		cfg.History = cfg.History[:maxHistoryEntries]
	}
	return cfg, nil
}

// --- Helpers on the parsed config -------------------------------------------

// runsAsRoot reports whether the configured user resolves to root. An unset
// user means "inherit", which for a from-scratch build is root; the second
// return value distinguishes the explicit case ("root"/"0") from the implicit
// one so the finding can be worded and scored honestly.
func (c containerConfig) runsAsRoot() (root, explicit bool) {
	u := strings.TrimSpace(c.User)
	// A "user:group" spec is judged by its user half.
	if i := strings.IndexAny(u, ":"); i >= 0 {
		u = u[:i]
	}
	switch u {
	case "":
		return true, false
	case "root", "0":
		return true, true
	default:
		return false, true
	}
}

// hasHealthcheck reports whether a real HEALTHCHECK probe is configured. A Test
// of ["NONE"] is Docker's explicit "disable inherited healthcheck" and counts
// as absent.
func (c containerConfig) hasHealthcheck() bool {
	if c.Healthcheck == nil || len(c.Healthcheck.Test) == 0 {
		return false
	}
	if len(c.Healthcheck.Test) == 1 && strings.EqualFold(c.Healthcheck.Test[0], "NONE") {
		return false
	}
	return true
}

// sortedPorts returns the exposed ports as sorted "port/proto" strings, so
// findings are deterministic regardless of JSON map iteration order.
func (c containerConfig) sortedPorts() []string {
	out := make([]string, 0, len(c.ExposedPorts))
	for p := range c.ExposedPorts {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// sortedVolumes returns the declared volume mount points, sorted.
func (c containerConfig) sortedVolumes() []string {
	out := make([]string, 0, len(c.Volumes))
	for v := range c.Volumes {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

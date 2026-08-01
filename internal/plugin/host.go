package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Manifest loading & host --------------------------------------------
//
// The host discovers plugins by reading *.json manifests from a directory. It
// validates each one, resolves its launch argv, and produces a Plugin ready to
// register. Loading is fail-soft per manifest: one broken manifest is reported
// but does not stop the others from loading.

// maxManifestBytes bounds a manifest file we will read, so a hostile file cannot
// exhaust memory during discovery.
const maxManifestBytes = 1 << 20 // 1 MiB

// Load reads and validates a single manifest file, returning a Plugin. The
// plugin's launch argv is resolved (${dir} expanded to the manifest directory)
// but the executable is not run.
func Load(path string) (*Plugin, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("manifest %s too large (%d bytes)", path, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	m.dir = filepath.Dir(path)
	return newPlugin(m)
}

// newPlugin validates a manifest and resolves its launch argv.
func newPlugin(m Manifest) (*Plugin, error) {
	if strings.TrimSpace(m.Name) == "" {
		return nil, fmt.Errorf("manifest has no name")
	}
	if len(m.Exec) == 0 {
		return nil, fmt.Errorf("plugin %q has no exec argv", m.Name)
	}
	argv := make([]string, len(m.Exec))
	for i, a := range m.Exec {
		argv[i] = strings.ReplaceAll(a, "${dir}", m.dir)
	}
	// The launch command must exist and must not be a directory. This is a
	// friendly early failure, not a security boundary (the command still runs
	// with a scrubbed env and its own process group).
	if _, err := os.Stat(argv[0]); err != nil {
		// A bare command name resolved via PATH is allowed; only reject an absolute
		// or relative path that does not exist.
		if strings.ContainsRune(argv[0], os.PathSeparator) {
			return nil, fmt.Errorf("plugin %q exec %q not found: %w", m.Name, argv[0], err)
		}
	}
	return &Plugin{manifest: m, argv: argv, runner: execRunner{}}, nil
}

// Host is a loaded set of plugins.
type Host struct {
	plugins []*Plugin
}

// LoadDir discovers and loads every *.json manifest in dir (non-recursive). It
// returns a Host with all valid plugins plus an error summarizing any that were
// skipped, so one bad manifest never hides the good ones. A missing directory is
// not an error — it yields an empty host (plugins are opt-in).
func LoadDir(dir string) (*Host, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &Host{}, nil
		}
		return nil, fmt.Errorf("read plugin dir %q: %w", dir, err)
	}
	h := &Host{}
	var skipped []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		p, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			skipped = append(skipped, e.Name()+" ("+err.Error()+")")
			continue
		}
		h.plugins = append(h.plugins, p)
	}
	sort.Slice(h.plugins, func(i, j int) bool { return h.plugins[i].Name() < h.plugins[j].Name() })
	if len(skipped) > 0 {
		return h, fmt.Errorf("skipped %d manifest(s): %v", len(skipped), skipped)
	}
	return h, nil
}

// Plugins returns the loaded plugins in name order.
func (h *Host) Plugins() []*Plugin { return h.plugins }

// Register adds every loaded plugin to the registry. The master calls this
// during integration when a plugin directory is configured (see NOTES.md):
//
//	if h, err := plugin.LoadDir(dir); err == nil { h.Register(reg) }
func (h *Host) Register(reg *engine.Registry) {
	for _, p := range h.plugins {
		reg.Register(p)
	}
}

// RegisterDir is the one-call convenience: load dir and register everything it
// contains into reg. It returns any load warning (skipped manifests) but always
// registers whatever loaded successfully.
func RegisterDir(reg *engine.Registry, dir string) error {
	h, err := LoadDir(dir)
	h.Register(reg)
	return err
}

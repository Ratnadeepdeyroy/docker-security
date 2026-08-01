package compliance

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file implements the data-driven compliance layer:
// versioned Control Packs (data, not code) load into a Unified Catalog, and a
// crosswalk lets one automated check satisfy many frameworks. Packs are JSON so
// the project stays dependency-free (no YAML library); the schema mirrors the
// plan's YAML control shape one-for-one.

//go:embed packs/*.json
var packFS embed.FS

// Pack is one framework version as data. Adding or updating a framework is a
// reviewed data change, never a code change.
type Pack struct {
	Framework string        `json:"framework"` // e.g. "cis-docker", "pci-dss-4.0.1"
	Version   string        `json:"version"`
	Title     string        `json:"title"`
	SourceURL string        `json:"source_url"`
	Controls  []PackControl `json:"controls"`
}

// PackControl is a single control: how it is assessed, which automated check
// evaluates it, and the crosswalk to every other framework it maps to.
type PackControl struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Statement  string `json:"statement,omitempty"`
	Level      int    `json:"level,omitempty"`
	Assessment string `json:"assessment"`       // automated|manual|inherited|hybrid
	Module     string `json:"module,omitempty"` // engine module that owns Check
	Check      string `json:"check,omitempty"`  // engine finding RuleID that evaluates it
	// PresentMeans flips check polarity: for most controls a matching finding is
	// a violation ("fail", the default); for evidence controls (e.g. "an SBOM was
	// generated") the finding's presence proves satisfaction ("pass").
	PresentMeans string              `json:"present_means,omitempty"`
	Expected     string              `json:"expected,omitempty"`
	Remediation  string              `json:"remediation,omitempty"`
	MapsTo       map[string][]string `json:"maps_to,omitempty"` // framework -> control ids
	References   []string            `json:"references,omitempty"`
}

// Catalog is the unified, normalized control catalog: every loaded pack keyed by
// framework, plus the crosswalk graph built from the packs' maps_to.
type Catalog struct {
	packs map[string]*Pack // framework -> pack
	order []string         // frameworks in load order
	xwalk map[string][]crosswalkEdge
}

type crosswalkEdge struct {
	Framework string
	ID        string
}

// LoadEmbeddedPacks loads the packs compiled into the binary.
func LoadEmbeddedPacks() (*Catalog, error) {
	entries, err := packFS.ReadDir("packs")
	if err != nil {
		return nil, fmt.Errorf("read embedded packs: %w", err)
	}
	cat := newCatalog()
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // deterministic load order
	for _, n := range names {
		data, err := packFS.ReadFile("packs/" + n)
		if err != nil {
			return nil, err
		}
		if err := cat.addJSON(data, n); err != nil {
			return nil, err
		}
	}
	cat.buildCrosswalk()
	return cat, nil
}

// LoadPacksFromDir loads packs from a directory (for user-supplied or updated
// packs), falling back to nothing if the directory is empty.
func LoadPacksFromDir(dir string) (*Catalog, error) {
	cat := newCatalog()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read packs dir %q: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		if err := cat.addJSON(data, n); err != nil {
			return nil, err
		}
	}
	cat.buildCrosswalk()
	return cat, nil
}

func newCatalog() *Catalog {
	return &Catalog{packs: map[string]*Pack{}, xwalk: map[string][]crosswalkEdge{}}
}

func (c *Catalog) addJSON(data []byte, name string) error {
	var p Pack
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse pack %q: %w", name, err)
	}
	if p.Framework == "" {
		return fmt.Errorf("pack %q has no framework", name)
	}
	if _, dup := c.packs[p.Framework]; !dup {
		c.order = append(c.order, p.Framework)
	}
	c.packs[p.Framework] = &p
	return nil
}

// buildCrosswalk indexes maps_to edges so a base control resolves to its
// equivalents in every other framework.
func (c *Catalog) buildCrosswalk() {
	for _, fw := range c.order {
		for _, ctl := range c.packs[fw].Controls {
			key := fw + "|" + ctl.ID
			for mfw, ids := range ctl.MapsTo {
				for _, id := range ids {
					c.xwalk[key] = append(c.xwalk[key], crosswalkEdge{Framework: mfw, ID: id})
				}
			}
		}
	}
}

// Frameworks lists loaded frameworks in load order.
func (c *Catalog) Frameworks() []string {
	out := make([]string, len(c.order))
	copy(out, c.order)
	return out
}

// Pack returns the pack for a framework, or nil.
func (c *Catalog) Pack(framework string) *Pack { return c.packs[framework] }

// Controls returns a framework's controls (empty if the framework is unknown).
func (c *Catalog) Controls(framework string) []PackControl {
	if p := c.packs[framework]; p != nil {
		return p.Controls
	}
	return nil
}

// MappedFrameworks returns the set of frameworks a control crosswalks to.
func (c *Catalog) MappedFrameworks(framework, id string) []crosswalkEdge {
	return c.xwalk[framework+"|"+id]
}

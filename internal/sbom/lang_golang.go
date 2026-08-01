package sbom

import (
	"bytes"
	"debug/buildinfo"
	"path"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// golangCataloger enumerates Go modules from two sources: build information
// embedded in compiled Go executables, and go.mod files (source side).
type golangCataloger struct{}

// maxGoBinarySize bounds the size of a file the cataloger will attempt to
// parse as a compiled Go binary. debug/buildinfo has to scan the file's
// symbol/data sections to find the embedded build info, so an oversized file
// (e.g. a multi-gigabyte data blob that happens to start with an ELF/Mach-O
// magic number) is skipped rather than paying that cost. It is a var, not a
// const, so tests can shrink it instead of allocating gigabytes of fixture
// data.
//
// This must not exceed internal/oci's own per-file read cap (maxFileBytes in
// internal/oci/loader.go, 256 MiB): the oci loader silently truncates a
// tar-sourced file's Data to that cap while leaving the reported Size at the
// tar header's uncapped value, so a file between 256 MiB and the old 512 MiB
// limit would pass this size gate with Data already truncated, causing
// buildinfo.Read to fail on truncated bytes with the error silently dropped
// (see fromBinary). Keeping the two caps equal means anything admitted here
// was read in full.
var maxGoBinarySize int64 = 256 << 20 // 256 MiB, matches oci's maxFileBytes

func (golangCataloger) Name() string { return "go-module" }

func (c golangCataloger) Catalog(tree *oci.FileTree, _ Distro) ([]Component, []Relationship, error) {
	var comps []Component
	for _, f := range tree.Files() {
		if f.Size <= maxGoBinarySize && looksLikeExecutable(f.Data) {
			comps = append(comps, c.fromBinary(f.Data, f.Path)...)
		}
		if path.Base(f.Path) == "go.mod" {
			comps = append(comps, c.fromGoMod(f.Data, f.Path)...)
		}
	}
	return comps, nil, nil
}

// readBuildInfo indirects debug/buildinfo.Read so a test can substitute a
// stand-in that panics, proving fromBinary's recover actually guards this
// call without depending on crafting real malformed-binary bytes that panic
// the current (well-hardened) stdlib parsers.
var readBuildInfo = buildinfo.Read

// fromBinary parses data as a compiled Go binary's embedded build info.
// looksLikeExecutable only checks a 4-byte magic number before data reaches
// here, so a crafted file with a valid magic prefix but structurally corrupt
// ELF/Mach-O/PE/Wasm internals could in principle panic deep inside
// debug/elf, debug/macho, debug/pe, or debug/plan9obj; the recover here
// downgrades that to "skip this file" instead of crashing the whole scan.
func (c golangCataloger) fromBinary(data []byte, srcPath string) (out []Component) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
		}
	}()
	bi, err := readBuildInfo(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	if bi.Main.Path != "" {
		out = append(out, c.component(bi.Main.Path, bi.Main.Version, "/"+srcPath, TypeApp))
	}
	for _, dep := range bi.Deps {
		if dep == nil {
			continue
		}
		m := dep
		if dep.Replace != nil {
			m = dep.Replace // record the effective (replacement) module
		}
		if m.Path == "" {
			continue
		}
		out = append(out, c.component(m.Path, m.Version, "/"+srcPath, TypeLibrary))
	}
	return out
}

func (c golangCataloger) fromGoMod(data []byte, srcPath string) []Component {
	var out []Component
	inRequireBlock := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := stripLineComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "module "):
			mod := strings.TrimSpace(strings.TrimPrefix(line, "module"))
			if mod != "" {
				out = append(out, c.component(mod, "", "/"+srcPath, TypeApp))
			}
		case strings.HasPrefix(line, "require ("):
			inRequireBlock = true
		case inRequireBlock && line == ")":
			inRequireBlock = false
		case inRequireBlock:
			if comp, ok := c.requireLine(line, srcPath); ok {
				out = append(out, comp)
			}
		case strings.HasPrefix(line, "require "):
			if comp, ok := c.requireLine(strings.TrimPrefix(line, "require "), srcPath); ok {
				out = append(out, comp)
			}
		}
	}
	return out
}

func (c golangCataloger) requireLine(line, srcPath string) (Component, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Component{}, false
	}
	return c.component(fields[0], fields[1], "/"+srcPath, TypeLibrary), true
}

func (c golangCataloger) component(modPath, version, src string, typ ComponentType) Component {
	ns, name := splitGoModule(modPath)
	return Component{
		Type:    typ,
		Name:    modPath,
		Version: version,
		Source:  src,
		FoundBy: c.Name(),
		PURL:    purl("golang", ns, name, version, nil),
	}
}

// splitGoModule splits a module path into (namespace, name) at the final slash.
func splitGoModule(modPath string) (string, string) {
	if i := strings.LastIndex(modPath, "/"); i >= 0 {
		return modPath[:i], modPath[i+1:]
	}
	return "", modPath
}

// stripLineComment removes a trailing "// ..." comment from a go.mod line.
func stripLineComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// looksLikeExecutable reports whether data begins with a magic number for a
// binary format that debug/buildinfo can read (ELF, Mach-O, PE, or Wasm).
func looksLikeExecutable(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch {
	case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}): // ELF
		return true
	case bytes.HasPrefix(data, []byte{'M', 'Z'}): // PE
		return true
	case bytes.HasPrefix(data, []byte{0x00, 'a', 's', 'm'}): // Wasm
		return true
	}
	// Mach-O (32/64-bit, little/big-endian) and universal ("fat") binaries.
	switch {
	case bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfa, 0xce}),
		bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfa, 0xcf}),
		bytes.HasPrefix(data, []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(data, []byte{0xcf, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(data, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return true
	}
	return false
}

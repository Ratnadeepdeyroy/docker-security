package harden

import (
	"fmt"
	"sort"
	"strings"
)

// --- Least-privilege AppArmor generation -------------------------------------
//
// AppArmor profiles are text, not JSON, and are loaded with apparmor_parser. We
// emit the same shape as the well-known docker-default template — tunables +
// abstractions/base, a capability list, an optional network rule, explicit file
// rules — but least-privilege: only the capabilities and paths the workload was
// observed to use are permitted, and a fixed block of dangerous paths is denied
// outright. Unlike seccomp, AppArmor is deny-by-default for any file class once
// you write a rule for it, so the explicit allow rules double as the confinement.
//
// The generated profile is meant to be reviewed by a human (or an agent) before
// loading; the deny block up top makes the intent obvious at a glance.

// AppArmorProfile is a generated profile broken into the pieces the renderer
// stitches together. Callers normally get one from GenerateAppArmor rather than
// building it by hand.
type AppArmorProfile struct {
	// Name is the profile name apparmor_parser registers, e.g. "dsecrat-web".
	Name string
	// Capabilities are the bare lower-case capability names to allow.
	Capabilities []string
	// Network allows network access when true (AppArmor's coarse "network,").
	Network bool
	// FileRules are rendered file-access lines ("<path> <modes>,"), already
	// sorted; deny rules come from the fixed baseline below.
	FileRules []string
}

// deniedPaths is the fixed block every generated profile denies regardless of
// observation. These are the classic container-escape and host-tampering
// surfaces: the docker socket, kernel-tampering procfs entries, raw kernel
// memory, sysfs writes, and the shadow file. Denying them explicitly means even
// a mistaken-but-broad allow rule below cannot re-open them.
var deniedPaths = []string{
	"deny /var/run/docker.sock rwklx,",
	"deny /run/docker.sock rwklx,",
	"deny @{PROC}/sysrq-trigger rwklx,",
	"deny @{PROC}/kcore rwklx,",
	"deny @{PROC}/kmem rwklx,",
	"deny @{PROC}/mem rwklx,",
	"deny @{PROC}/sys/kernel/** wklx,",
	"deny /sys/[^f]*/** wklx,",     // everything under /sys except /sys/fs
	"deny /sys/f[^s]*/** wklx,",    // ...and /sys/f* that is not /sys/fs
	"deny /sys/firmware/** rwklx,", // ACPI/EFI tables
	"deny /etc/shadow rwklx,",
	"deny /etc/gshadow rwklx,",
}

// GenerateAppArmor builds a least-privilege AppArmor profile from an observation.
// Observed capabilities and file accesses become allow rules; the dangerous-path
// block is always denied. Output is deterministic (all rule sets are sorted).
func GenerateAppArmor(obs Observation, name string) *AppArmorProfile {
	if name == "" {
		name = "dsecrat-generated"
	}
	name = sanitizeProfileName(name)

	p := &AppArmorProfile{
		Name:    name,
		Network: obs.Network,
	}

	// Capabilities: docker-default grants a broad set; we grant only what we saw.
	caps := make([]string, 0, len(obs.Capabilities))
	for _, c := range obs.capSet() {
		caps = append(caps, strings.ToLower(c))
	}
	sort.Strings(caps)
	p.Capabilities = caps

	// File rules, one per (path, mode) with modes merged when a path appears in
	// several access sets. AppArmor modes: r read, w write, ix "inherit exec"
	// (run the target confined by this profile). We use ix for execs so spawned
	// helpers stay confined rather than running unconstrained (Ux/Px).
	modes := map[string]string{}
	addMode := func(path, m string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		modes[path] = mergeModes(modes[path], m)
	}
	for _, f := range obs.FileReads {
		addMode(f, "r")
	}
	for _, f := range obs.FileWrites {
		addMode(f, "w")
	}
	for _, f := range obs.FileExecs {
		addMode(f, "ix")
	}

	rules := make([]string, 0, len(modes))
	for path, m := range modes {
		rules = append(rules, fmt.Sprintf("%s %s,", path, m))
	}
	sort.Strings(rules)
	p.FileRules = rules
	return p
}

// Render produces the full AppArmor profile text, ready to write to
// /etc/apparmor.d and load with apparmor_parser. The layout mirrors
// docker-default so it reads familiarly to anyone who has seen one.
func (p *AppArmorProfile) Render() string {
	var b strings.Builder
	b.WriteString("#include <tunables/global>\n\n")
	// attach_disconnected: keep confining a process whose mount moved out from
	// under it. mediate_deleted: keep mediating access to unlinked files.
	fmt.Fprintf(&b, "profile %s flags=(attach_disconnected,mediate_deleted) {\n", p.Name)
	b.WriteString("  #include <abstractions/base>\n\n")

	// Deny block first so intent is unmistakable and it cannot be widened below.
	b.WriteString("  # --- always denied: escape & host-tampering surfaces ---\n")
	for _, d := range deniedPaths {
		fmt.Fprintf(&b, "  %s\n", d)
	}
	b.WriteString("\n")

	if len(p.Capabilities) > 0 {
		b.WriteString("  # --- observed capabilities ---\n")
		for _, c := range p.Capabilities {
			fmt.Fprintf(&b, "  capability %s,\n", c)
		}
		b.WriteString("\n")
	}

	if p.Network {
		b.WriteString("  # --- observed network use ---\n")
		b.WriteString("  network,\n\n")
	}

	if len(p.FileRules) > 0 {
		b.WriteString("  # --- observed file access ---\n")
		for _, r := range p.FileRules {
			fmt.Fprintf(&b, "  %s\n", r)
		}
	}

	b.WriteString("}\n")
	return b.String()
}

// mergeModes unions two AppArmor mode strings, preserving a stable rwix-ish
// order and treating multi-character tokens like "ix" atomically.
func mergeModes(a, b string) string {
	set := map[string]bool{}
	for _, m := range []string{a, b} {
		for _, tok := range splitModes(m) {
			set[tok] = true
		}
	}
	// Canonical order: read, write, then exec form.
	order := []string{"r", "w", "ix", "ux", "px"}
	var out strings.Builder
	for _, tok := range order {
		if set[tok] {
			out.WriteString(tok)
			delete(set, tok)
		}
	}
	// Any leftover tokens (defensive) appended sorted.
	rest := make([]string, 0, len(set))
	for tok := range set {
		rest = append(rest, tok)
	}
	sort.Strings(rest)
	out.WriteString(strings.Join(rest, ""))
	return out.String()
}

// splitModes tokenises an AppArmor mode string, keeping "ix"/"ux"/"px" whole.
func splitModes(m string) []string {
	var toks []string
	for i := 0; i < len(m); {
		if i+1 < len(m) && m[i+1] == 'x' {
			toks = append(toks, m[i:i+2])
			i += 2
			continue
		}
		toks = append(toks, m[i:i+1])
		i++
	}
	return toks
}

// sanitizeProfileName keeps a profile name to the characters apparmor_parser is
// happy with (alnum, dash, underscore, dot), so a workload label can be used
// directly without breaking the profile header.
func sanitizeProfileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if out == "" {
		return "dsecrat-generated"
	}
	return out
}

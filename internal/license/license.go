// Package license implements license-policy evaluation over an SBOM: it turns
// the licenses the SBOM already detects (internal/sbom captures them per
// component) into a gate. Detection without a gate leaves domain 1's
// license-policy control unattained; this package closes it.
//
// The evaluation is pure and deterministic — given a component's licenses and a
// Policy, Evaluate returns a fixed verdict — so it unit-tests without any I/O.
// The engine module (internal/modules/license) wires it to SBOM generation and
// the Finding stream, which feeds the existing `dsecrat policy eval` CI gate.
package license

import (
	"sort"
	"strings"
)

// Class is the risk category a license falls into for policy purposes. The tiers
// matter because most orgs care less about a specific SPDX id than about the
// obligation category: permissive is fine, strong copyleft in a distributed
// image is usually the thing to block.
type Class string

const (
	// ClassPermissive: MIT/BSD/Apache-style — minimal obligations.
	ClassPermissive Class = "permissive"
	// ClassWeakCopyleft: LGPL/MPL/EPL — file/library-level copyleft.
	ClassWeakCopyleft Class = "weak-copyleft"
	// ClassStrongCopyleft: GPL family — whole-work copyleft.
	ClassStrongCopyleft Class = "strong-copyleft"
	// ClassNetworkCopyleft: AGPL — copyleft triggered by network use.
	ClassNetworkCopyleft Class = "network-copyleft"
	// ClassUnknown: unrecognized or missing license.
	ClassUnknown Class = "unknown"
)

// classify maps a normalized SPDX-ish id to a Class. Matching is case-insensitive
// and prefix-based for family members (GPL-2.0-only, GPL-3.0-or-later, …).
func classify(id string) Class {
	u := strings.ToUpper(strings.TrimSpace(id))
	if u == "" {
		return ClassUnknown
	}
	switch {
	case strings.HasPrefix(u, "AGPL"):
		return ClassNetworkCopyleft
	case strings.HasPrefix(u, "LGPL"):
		return ClassWeakCopyleft
	case strings.HasPrefix(u, "MPL"), strings.HasPrefix(u, "EPL"),
		strings.HasPrefix(u, "CDDL"), u == "CPL-1.0":
		return ClassWeakCopyleft
	case strings.HasPrefix(u, "GPL"), u == "SLEEPYCAT",
		strings.HasPrefix(u, "OSL"), u == "EUPL-1.2", strings.HasPrefix(u, "CECILL"):
		return ClassStrongCopyleft
	}
	for _, p := range permissiveIDs {
		if u == p {
			return ClassPermissive
		}
	}
	return ClassUnknown
}

// permissiveIDs is the recognized set of common permissive SPDX ids. Anything
// not classified into a copyleft family and not in this set is ClassUnknown,
// which a strict policy can also gate on.
var permissiveIDs = []string{
	"MIT", "MIT-0", "ISC", "APACHE-2.0", "APACHE-1.1", "BSD-2-CLAUSE",
	"BSD-3-CLAUSE", "BSD-3-CLAUSE-CLEAR", "0BSD", "BSL-1.0", "ZLIB",
	"UNLICENSE", "CC0-1.0", "PYTHON-2.0", "PSF-2.0", "WTFPL", "X11",
	"BLUEOAK-1.0.0", "ARTISTIC-2.0", "NCSA",
}

// Verdict is the policy outcome for one component's license set.
type Verdict struct {
	// Denied is true when policy forbids at least one of the component's licenses.
	Denied bool
	// Reason names the specific finding class (see below).
	Reason Reason
	// License is the specific offending (or unknown) license id/name that drove
	// the verdict; empty when the component declared none.
	License string
	// Class is the offending license's class.
	Class Class
}

// Reason enumerates why a component failed the license policy.
type Reason string

const (
	ReasonNone       Reason = ""
	ReasonDenied     Reason = "denied-license"      // explicitly on the deny list or a denied class
	ReasonNotAllowed Reason = "not-in-allowlist"    // allowlist set and license not on it
	ReasonUnknown    Reason = "unknown-license"     // policy flags unknown/unrecognized
	ReasonUnlicensed Reason = "no-license-declared" // policy flags missing license
)

// Policy is the license gate configuration. All fields are optional; an empty
// Policy denies nothing.
type Policy struct {
	// Allow, if non-empty, is an allowlist of SPDX ids; any license not on it is
	// denied (ReasonNotAllowed). Case-insensitive.
	Allow []string
	// Deny is a denylist of SPDX ids, applied even when Allow is empty.
	Deny []string
	// DenyClasses denies entire license classes (e.g. strong-copyleft).
	DenyClasses []Class
	// FlagUnknown denies components whose license is unrecognized.
	FlagUnknown bool
	// FlagUnlicensed denies components that declare no license at all.
	FlagUnlicensed bool

	allowSet map[string]bool
	denySet  map[string]bool
	denyCls  map[Class]bool
}

// index builds the case-insensitive lookup sets. Callers must not mutate the
// slices after calling Evaluate.
func (p *Policy) index() {
	if p.allowSet != nil {
		return
	}
	p.allowSet = upperSet(p.Allow)
	p.denySet = upperSet(p.Deny)
	p.denyCls = map[Class]bool{}
	for _, c := range p.DenyClasses {
		p.denyCls[c] = true
	}
}

// Empty reports whether the policy would never deny anything, so a module can
// skip emitting findings entirely.
func (p *Policy) Empty() bool {
	return len(p.Allow) == 0 && len(p.Deny) == 0 && len(p.DenyClasses) == 0 &&
		!p.FlagUnknown && !p.FlagUnlicensed
}

// LicenseID is the id/name pair the SBOM records for a license. Evaluate accepts
// the SPDX id when present, else the free-text name.
type LicenseID struct {
	ID   string
	Name string
}

func (l LicenseID) value() string {
	if l.ID != "" {
		return l.ID
	}
	return l.Name
}

// Evaluate returns the policy verdict for a component's declared licenses. The
// component fails on the first offending license (checked deny → allowlist →
// unknown), so the reported License is the concrete cause. A component with no
// declared licenses is denied only when FlagUnlicensed is set.
func (p *Policy) Evaluate(licenses []LicenseID) Verdict {
	p.index()

	present := make([]LicenseID, 0, len(licenses))
	for _, l := range licenses {
		if l.value() != "" {
			present = append(present, l)
		}
	}
	if len(present) == 0 {
		if p.FlagUnlicensed {
			return Verdict{Denied: true, Reason: ReasonUnlicensed, Class: ClassUnknown}
		}
		return Verdict{}
	}

	// Deterministic order: evaluate licenses in a stable sort so the reported
	// cause does not depend on SBOM iteration order.
	sort.SliceStable(present, func(i, j int) bool { return present[i].value() < present[j].value() })

	for _, l := range present {
		v := l.value()
		u := strings.ToUpper(v)
		cls := classify(v)

		if p.denySet[u] {
			return Verdict{Denied: true, Reason: ReasonDenied, License: v, Class: cls}
		}
		if p.denyCls[cls] {
			return Verdict{Denied: true, Reason: ReasonDenied, License: v, Class: cls}
		}
		if p.FlagUnknown && cls == ClassUnknown {
			return Verdict{Denied: true, Reason: ReasonUnknown, License: v, Class: cls}
		}
		if len(p.allowSet) > 0 && !p.allowSet[u] {
			return Verdict{Denied: true, Reason: ReasonNotAllowed, License: v, Class: cls}
		}
	}
	return Verdict{}
}

// Classify exposes the license classifier for callers that want the category
// without a full policy evaluation.
func Classify(id string) Class { return classify(id) }

func upperSet(in []string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s != "" {
			m[s] = true
		}
	}
	return m
}

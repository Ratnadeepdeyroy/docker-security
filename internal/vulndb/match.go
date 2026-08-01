package vulndb

// --- Range matching ------------------------------------------------------

// rangeScheme resolves the comparison scheme for a range: its explicit override
// if set, otherwise the fallback (the ecosystem default) supplied by the caller.
func rangeScheme(r Range, fallback VersionScheme) VersionScheme {
	if r.Scheme != "" {
		return r.Scheme
	}
	return fallback
}

// Vulnerable reports whether an installed version falls inside any of the
// advisory's affected ranges, comparing with the given scheme.
//
// A range is "[Introduced, Fixed)" (Fixed exclusive) or "[Introduced,
// LastAffected]" (LastAffected inclusive) or, with neither upper bound, an open
// "[Introduced, ∞)". Introduced of "" or "0" means unbounded below. An empty
// installed version can never be judged and is treated as not-vulnerable, so a
// component we could not version never raises a (false) finding.
func Vulnerable(sch VersionScheme, installed string, ranges []Range) bool {
	if installed == "" {
		return false
	}
	for _, r := range ranges {
		if inRange(rangeScheme(r, sch), installed, r) {
			return true
		}
	}
	return false
}

// inRange tests a single interval.
func inRange(sch VersionScheme, installed string, r Range) bool {
	// Lower bound: introduced (inclusive). "" and "0" mean no lower bound.
	if r.Introduced != "" && r.Introduced != "0" {
		if Compare(sch, installed, r.Introduced) < 0 {
			return false
		}
	}
	// Upper bound: fixed (exclusive) takes precedence over last_affected.
	switch {
	case r.Fixed != "":
		return Compare(sch, installed, r.Fixed) < 0
	case r.LastAffected != "":
		return Compare(sch, installed, r.LastAffected) <= 0
	default:
		// Open-ended range: everything at or above Introduced is affected.
		return true
	}
}

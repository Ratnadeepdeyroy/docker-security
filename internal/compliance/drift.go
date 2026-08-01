package compliance

import "sort"

// --- Drift-from-baseline ---------------------------------------------------

// Change classifies how one control moved between two runs.
type Change string

const (
	// ChangeRegressed: was compliant (PASS), now failing/warning — the alarming case.
	ChangeRegressed Change = "regressed"
	// ChangeFixed: was failing/warning, now PASS — a win to celebrate in the narrative.
	ChangeFixed Change = "fixed"
	// ChangeNew: control exists now but not in the baseline (catalogue grew or first run).
	ChangeNew Change = "new"
	// ChangeRemoved: control was in the baseline but not now (profile change).
	ChangeRemoved Change = "removed"
	// ChangeUnchanged: same effective status in both runs.
	ChangeUnchanged Change = "unchanged"
)

// DriftEntry is one control's movement between baseline and current.
type DriftEntry struct {
	ControlID string `json:"control_id"`
	Title     string `json:"title"`
	Change    Change `json:"change"`
	From      Status `json:"from"`
	To        Status `json:"to"`
}

// Drift is the per-control delta between an earlier baseline report and the
// current one. It is the raw material for "flag the specific drifted control"
// and for the continuous-compliance narrative's since-last-run section.
type Drift struct {
	Benchmark string       `json:"benchmark"`
	Regressed []DriftEntry `json:"regressed,omitempty"`
	Fixed     []DriftEntry `json:"fixed,omitempty"`
	New       []DriftEntry `json:"new,omitempty"`
	Removed   []DriftEntry `json:"removed,omitempty"`
	ScoreFrom int          `json:"score_from"`
	ScoreTo   int          `json:"score_to"`
}

// HasDrift reports whether anything meaningful moved (ignores unchanged and the
// first-run "everything is new" case, which callers usually want to treat as a
// baseline rather than drift).
func (d *Drift) HasDrift() bool {
	return len(d.Regressed) > 0 || len(d.Fixed) > 0 || len(d.Removed) > 0
}

// Diff compares a baseline report against the current one and returns the drift.
// Comparison is on effective status (waivers demoted) and keyed by control id,
// so it is stable across reorderings and deterministic. A nil baseline yields a
// drift where every current control is "new" (the honest first-run answer).
func Diff(baseline, current *Report) *Drift {
	d := &Drift{Benchmark: current.Benchmark, ScoreTo: current.Score()}

	base := map[string]Result{}
	if baseline != nil {
		d.ScoreFrom = baseline.Score()
		for _, r := range baseline.Results {
			base[r.Control.ID] = r
		}
	}
	curIDs := map[string]bool{}

	for _, cur := range current.Results {
		curIDs[cur.Control.ID] = true
		prev, ok := base[cur.Control.ID]
		if !ok {
			d.New = append(d.New, entry(cur, ChangeNew, StatusUnknown, cur.effectiveStatus()))
			continue
		}
		from, to := prev.effectiveStatus(), cur.effectiveStatus()
		switch {
		case from == StatusPass && (to == StatusFail || to == StatusWarn):
			d.Regressed = append(d.Regressed, entry(cur, ChangeRegressed, from, to))
		case (from == StatusFail || from == StatusWarn) && to == StatusPass:
			d.Fixed = append(d.Fixed, entry(cur, ChangeFixed, from, to))
		}
	}
	// Controls present in the baseline but gone now (e.g. profile narrowed).
	for id, prev := range base {
		if !curIDs[id] {
			d.Removed = append(d.Removed, entry(prev, ChangeRemoved, prev.effectiveStatus(), StatusUnknown))
		}
	}

	sortEntries(d.Regressed)
	sortEntries(d.Fixed)
	sortEntries(d.New)
	sortEntries(d.Removed)
	return d
}

func entry(r Result, ch Change, from, to Status) DriftEntry {
	return DriftEntry{ControlID: r.Control.ID, Title: r.Control.Title, Change: ch, From: from, To: to}
}

func sortEntries(es []DriftEntry) {
	sort.SliceStable(es, func(i, j int) bool { return compareControlID(es[i].ControlID, es[j].ControlID) })
}

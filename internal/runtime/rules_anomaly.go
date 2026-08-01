package runtime

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// This file holds behavioral-anomaly detection: deviation from a learned
// baseline of normal behavior. Signatures catch known-bad; anomaly catches
// never-before-seen behavior for a workload, which is the door to zero-day and
// living-off-the-land activity that no signature covers. It is OFF BY DEFAULT
// and inert without a supplied baseline — an intelligence layer atop the
// deterministic signature core, never a gate on correctness (SHARED_CONTRACT §4).

// --- DS-RAT-RT-050 behavioral anomaly ----------------------------------------

type anomalyRule struct {
	ruleBase
	enabled  bool
	baseline *Baseline
}

func newAnomalyRule(opts Options) Rule {
	return &anomalyRule{
		ruleBase: ruleBase{
			id: "DS-RAT-RT-050",
			info: RuleInfo{
				Title:       "Behavioral anomaly (deviation from baseline)",
				Severity:    engine.SeverityMedium,
				Technique:   techPromptInject, // generic execution/behavior deviation
				Default:     false,
				Description: "A workload performed an action outside its learned behavioral baseline: an executable, syscall, or network endpoint never seen during the trusted learning window. Anomaly detection provides zero-day coverage beyond signatures.",
				Remediation: "Review the deviation against expected behavior. If legitimate, extend the baseline; if not, treat as a potential compromise and pivot to the signature detections for confirmation.",
			},
		},
		enabled:  opts.EnableAnomaly && opts.Baseline != nil,
		baseline: opts.Baseline,
	}
}

func (r *anomalyRule) Evaluate(ev *Event, st *State) []Detection {
	if !r.enabled {
		return nil // off by default, and inert without a baseline
	}
	wp := r.baseline.Workloads[workloadKey(ev.Container)]
	if wp == nil {
		return nil // no baseline for this workload → cannot judge deviation
	}
	switch ev.Kind {
	case KindProcess:
		if ev.Process.Exe != "" && !wp.knowsExe(ev.Process.Exe) {
			// De-dupe: one anomaly per novel exe per container.
			if st.markExec(containerKey(ev.Container)+"|anomaly", ev.Process.Exe) {
				return []Detection{r.fire(ev, "unbaselined executable "+ev.Process.Exe+" (pid "+itoa(ev.Process.PID)+")",
					map[string]string{"kind": "exe", "value": ev.Process.Exe})}
			}
		}
	case KindSyscall:
		if ev.Syscall != nil && ev.Syscall.Name != "" && !wp.knowsSyscall(ev.Syscall.Name) {
			return []Detection{r.fire(ev, "unbaselined syscall "+ev.Syscall.Name,
				map[string]string{"kind": "syscall", "value": ev.Syscall.Name})}
		}
	case KindNetwork:
		if ev.Network != nil {
			if ep := endpointKey(ev.Network); ep != "" && !wp.knowsEndpoint(ep) {
				if st.markConnect(containerKey(ev.Container)+"|anomaly", ep) {
					return []Detection{r.fire(ev, "unbaselined network endpoint "+ep,
						map[string]string{"kind": "endpoint", "value": ep})}
				}
			}
		}
	}
	return nil
}

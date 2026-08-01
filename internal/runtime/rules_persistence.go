package runtime

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file holds the persistence rule: writes to well-known autostart/autorun
// locations, and dynamic-linker hijacking via LD_PRELOAD, either persisted to
// disk (/etc/ld.so.preload) or injected at exec time via the environment.

// --- DS-RAT-RT-011 persistence mechanism -------------------------------------

// persistenceWritePaths are prefix/exact locations whose modification installs
// a persistence mechanism (cron, systemd units, sysvinit scripts, rc.local, the
// dynamic-linker preload list).
var persistenceWritePaths = []string{
	"/etc/ld.so.preload",
	"/etc/cron",
	"/var/spool/cron",
	"/etc/systemd/",
	"/etc/init.d/",
	"/etc/rc.local",
}

// persistenceWriteSuffixes are path suffixes whose modification installs a
// persistence mechanism via shell-startup files or SSH key trust.
var persistenceWriteSuffixes = []string{
	"/.bashrc",
	"/.bash_profile",
	"/.profile",
	"authorized_keys",
}

// hasAnySuffix reports whether p ends with any of the suffixes.
func hasAnySuffix(p string, suffixes []string) (string, bool) {
	for _, s := range suffixes {
		if strings.HasSuffix(p, s) {
			return s, true
		}
	}
	return "", false
}

type persistenceRule struct{ ruleBase }

func newPersistenceRule() Rule {
	return &persistenceRule{ruleBase{
		id: "DS-RAT-RT-011",
		info: RuleInfo{
			Title:       "Persistence mechanism",
			Severity:    engine.SeverityHigh,
			Technique:   techHijackExecFlow,
			Default:     true,
			Description: "A process wrote to a well-known autostart/autorun location (cron, systemd, init.d, rc.local, shell startup files, ld.so.preload, authorized_keys) or launched a process with LD_PRELOAD set on its command line — both are dynamic-linker/execution-flow hijacking techniques used to survive restarts or hook every subsequent process. (LD_PRELOAD passed purely via the environment, rather than argv, is only visible to the eBPF sensor.)",
			Remediation: "Enforce a read-only root filesystem and alert on any write to autostart locations. Restrict LD_PRELOAD via seccomp/AppArmor or by disabling it for the container's user namespace; investigate any process launched with it set.",
		},
	}}
}

func (r *persistenceRule) Evaluate(ev *Event, st *State) []Detection {
	switch ev.Kind {
	case KindFile:
		if ev.File == nil || !fileIsWrite(ev.File) {
			return nil
		}
		if pre, ok := matchesAnyPrefix(ev.File.Path, persistenceWritePaths); ok {
			return []Detection{r.fire(ev, "write to persistence location "+ev.File.Path+" ("+ev.File.Op+")",
				map[string]string{"path": ev.File.Path, "op": ev.File.Op, "matched": pre, "vector": "file"})}
		}
		if suf, ok := hasAnySuffix(ev.File.Path, persistenceWriteSuffixes); ok {
			return []Detection{r.fire(ev, "write to persistence location "+ev.File.Path+" ("+ev.File.Op+")",
				map[string]string{"path": ev.File.Path, "op": ev.File.Op, "matched": suf, "vector": "file"})}
		}
	case KindProcess:
		for _, a := range ev.Process.Args {
			if strings.Contains(a, "LD_PRELOAD=") {
				return []Detection{r.fire(ev, "process executed with LD_PRELOAD set — dynamic-linker hijack",
					map[string]string{"vector": "ld_preload"})}
			}
		}
	}
	return nil
}

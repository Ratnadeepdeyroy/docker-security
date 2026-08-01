package runtime

import "sort"

// --- Behavioral baseline --------------------------------------------------

// Baseline is a learned profile of a workload's normal behavior: the syscalls,
// executables, and egress endpoints observed during a trusted learning window,
// grouped by image. It powers two things: anomaly detection (deviation from
// normal, catching zero-days no signature covers) and least-privilege profile
// generation (turn "what it actually did" into "what it is allowed to do").
//
// It is a plain, serializable value so a baseline can be recorded once and
// replayed deterministically — no model, no training run, no clock.
type Baseline struct {
	Version string `json:"version"`
	// Workloads maps an image identifier to its observed behavior.
	Workloads map[string]*WorkloadProfile `json:"workloads"`
}

// WorkloadProfile is the observed behavior of a single image/workload. Sets are
// stored as sorted slices for stable, diffable serialization.
//
// It carries more than seccomp needs on purpose: the capability and file-access
// fields make it a complete least-privilege input, so the Phase 7 hardening
// generator (AppArmor/seccomp) can be fed by a trivial field-copy adapter into
// its harden.Observation type — see NOTES.md.
type WorkloadProfile struct {
	Image        string   `json:"image"`
	Syscalls     []string `json:"syscalls,omitempty"`
	Exes         []string `json:"exes,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"` // "ip:port" or domain
	Capabilities []string `json:"capabilities,omitempty"`
	FileReads    []string `json:"file_reads,omitempty"`
	FileWrites   []string `json:"file_writes,omitempty"`
	FileExecs    []string `json:"file_execs,omitempty"`
	Network      bool     `json:"network,omitempty"`
}

// has reports set membership via binary search (slices are kept sorted).
func contains(sorted []string, v string) bool {
	i := sort.SearchStrings(sorted, v)
	return i < len(sorted) && sorted[i] == v
}

// Syscall/Exe/Endpoint membership helpers used by the anomaly rule.
func (w *WorkloadProfile) knowsSyscall(name string) bool { return contains(w.Syscalls, name) }
func (w *WorkloadProfile) knowsExe(exe string) bool      { return contains(w.Exes, exe) }
func (w *WorkloadProfile) knowsEndpoint(ep string) bool  { return contains(w.Endpoints, ep) }

// --- Learning accumulator -------------------------------------------------

// baselineAccumulator collects behavior during a learning run and builds an
// immutable Baseline at the end. Kept separate from Baseline so the learned
// artifact is a clean value with no mutation machinery attached.
type baselineAccumulator struct {
	workloads map[string]*profileSets
}

type profileSets struct {
	image      string
	syscalls   map[string]struct{}
	exes       map[string]struct{}
	endpoints  map[string]struct{}
	caps       map[string]struct{}
	fileReads  map[string]struct{}
	fileWrites map[string]struct{}
	fileExecs  map[string]struct{}
	network    bool
}

func newBaselineAccumulator() *baselineAccumulator {
	return &baselineAccumulator{workloads: map[string]*profileSets{}}
}

// record folds one event into the accumulating profile for its workload. It
// captures the full least-privilege surface (syscalls, capabilities, file access
// by mode, network use), not just what seccomp needs, so the profile can drive
// AppArmor generation too.
func (a *baselineAccumulator) record(ev *Event) {
	key := workloadKey(ev.Container)
	if key == "" {
		return
	}
	ps := a.workloads[key]
	if ps == nil {
		ps = &profileSets{
			image:      workloadImage(ev.Container),
			syscalls:   map[string]struct{}{},
			exes:       map[string]struct{}{},
			endpoints:  map[string]struct{}{},
			caps:       map[string]struct{}{},
			fileReads:  map[string]struct{}{},
			fileWrites: map[string]struct{}{},
			fileExecs:  map[string]struct{}{},
		}
		a.workloads[key] = ps
	}
	// Capabilities travel on the process record regardless of event kind.
	for _, c := range ev.Process.Caps {
		ps.caps[c] = struct{}{}
	}
	switch ev.Kind {
	case KindProcess:
		if ev.Process.Exe != "" {
			ps.exes[ev.Process.Exe] = struct{}{}
			ps.fileExecs[ev.Process.Exe] = struct{}{}
		}
		// An exec is a clone+execve; record the canonical syscall so the
		// generated seccomp profile permits process startup.
		ps.syscalls["execve"] = struct{}{}
	case KindSyscall:
		if ev.Syscall != nil && ev.Syscall.Name != "" {
			ps.syscalls[ev.Syscall.Name] = struct{}{}
		}
	case KindNetwork:
		if ev.Network != nil {
			if ep := endpointKey(ev.Network); ep != "" {
				ps.endpoints[ep] = struct{}{}
			}
			ps.syscalls["connect"] = struct{}{}
			ps.network = true
		}
	case KindFile:
		ps.syscalls["openat"] = struct{}{}
		if ev.File != nil && ev.File.Path != "" {
			if fileIsWrite(ev.File) {
				ps.fileWrites[ev.File.Path] = struct{}{}
			} else {
				ps.fileReads[ev.File.Path] = struct{}{}
			}
		}
	}
}

// build freezes the accumulator into a deterministic Baseline (sorted sets).
func (a *baselineAccumulator) build() *Baseline {
	b := &Baseline{Version: RuleSetVersion, Workloads: map[string]*WorkloadProfile{}}
	for key, ps := range a.workloads {
		b.Workloads[key] = &WorkloadProfile{
			Image:        ps.image,
			Syscalls:     sortedKeys(ps.syscalls),
			Exes:         sortedKeys(ps.exes),
			Endpoints:    sortedKeys(ps.endpoints),
			Capabilities: sortedKeys(ps.caps),
			FileReads:    sortedKeys(ps.fileReads),
			FileWrites:   sortedKeys(ps.fileWrites),
			FileExecs:    sortedKeys(ps.fileExecs),
			Network:      ps.network,
		}
	}
	return b
}

// --- keys ----------------------------------------------------------------

// workloadKey identifies the workload a baseline is keyed by — the image, so a
// profile generalizes across replicas of the same image.
func workloadKey(c ContainerInfo) string {
	if c.ImageID != "" {
		return c.ImageID
	}
	return c.ImageRef
}

func workloadImage(c ContainerInfo) string {
	if c.ImageRef != "" {
		return c.ImageRef
	}
	return c.ImageID
}

// endpointKey renders a network event as a stable endpoint string, preferring a
// domain when present, else ip:port.
func endpointKey(n *NetworkEvent) string {
	if n.Domain != "" {
		return n.Domain
	}
	if n.RemoteIP == "" {
		return ""
	}
	if n.RemotePort != 0 {
		return n.RemoteIP + ":" + itoa(n.RemotePort)
	}
	return n.RemoteIP
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

package runtime

// --- Accumulated detection state -----------------------------------------

// State is the memory the detector carries across events in a stream. Rules read
// it to reason about context ("has this container run this binary before?",
// "what is this process's lineage?") and update it as events flow. It is owned
// by a single Detector and touched from one goroutine, so it needs no locking.
type State struct {
	// procs is the live process table, keyed by PID, rebuilt from process
	// events. It lets rules resolve ancestry and parent context even when an
	// individual event carries only a partial chain.
	procs map[int]ProcessInfo
	// imageBinaries maps an image identifier (ID preferred, else ref) to the set
	// of executable paths that shipped in it — the drift baseline.
	imageBinaries map[string]map[string]struct{}
	// execSeen records, per container, which executables have already run, so a
	// rule can fire once per novel binary rather than on every exec.
	execSeen map[string]map[string]struct{}
	// firstConnect records whether a container has connected to a given remote
	// endpoint before, supporting "first contact with a new endpoint" logic.
	connectSeen map[string]map[string]struct{}
	// baselineAcc accumulates observed behavior when learning a Baseline.
	baselineAcc *baselineAccumulator
}

// newState builds an empty State seeded with the given image inventory.
func newState(images []ImageInventory) *State {
	st := &State{
		procs:         map[int]ProcessInfo{},
		imageBinaries: map[string]map[string]struct{}{},
		execSeen:      map[string]map[string]struct{}{},
		connectSeen:   map[string]map[string]struct{}{},
	}
	for _, img := range images {
		set := make(map[string]struct{}, len(img.Binaries))
		for _, b := range img.Binaries {
			set[b] = struct{}{}
		}
		if img.ImageID != "" {
			st.imageBinaries[img.ImageID] = set
		}
		if img.ImageRef != "" {
			st.imageBinaries[img.ImageRef] = set
		}
	}
	return st
}

// observe updates the process table before rules run, so a rule can look up the
// acting process and its parent consistently.
func (st *State) observe(ev *Event) {
	if ev.Kind == KindProcess && ev.Process.PID != 0 {
		st.procs[ev.Process.PID] = ev.Process
	}
}

// imageInventory returns the known binary set for an event's container, and
// whether an inventory exists. Drift rules must not fire when the inventory is
// unknown (empty ok=false), to avoid flagging everything on missing data.
func (st *State) imageInventory(c ContainerInfo) (map[string]struct{}, bool) {
	if set, ok := st.imageBinaries[c.ImageID]; ok && c.ImageID != "" {
		return set, true
	}
	if set, ok := st.imageBinaries[c.ImageRef]; ok && c.ImageRef != "" {
		return set, true
	}
	return nil, false
}

// markExec records an executable as seen for a container and reports whether it
// was novel (first time seen). Used to fire drift/shell once per new binary.
func (st *State) markExec(containerKey, exe string) (novel bool) {
	set := st.execSeen[containerKey]
	if set == nil {
		set = map[string]struct{}{}
		st.execSeen[containerKey] = set
	}
	if _, ok := set[exe]; ok {
		return false
	}
	set[exe] = struct{}{}
	return true
}

// markConnect records a remote endpoint as contacted by a container and reports
// whether it was the first such contact.
func (st *State) markConnect(containerKey, endpoint string) (novel bool) {
	set := st.connectSeen[containerKey]
	if set == nil {
		set = map[string]struct{}{}
		st.connectSeen[containerKey] = set
	}
	if _, ok := set[endpoint]; ok {
		return false
	}
	set[endpoint] = struct{}{}
	return true
}

// containerKey returns a stable identity for a container for per-container
// bookkeeping, preferring the container id and falling back to image+name.
func containerKey(c ContainerInfo) string {
	if c.ID != "" {
		return c.ID
	}
	if c.Name != "" {
		return c.Name + "@" + c.ImageRef
	}
	return c.ImageRef
}

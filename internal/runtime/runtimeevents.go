// Package runtime (this file): container attribution from cgroup lines.
//
// This is an opt-in host integration, in the same spirit as internal/dockercli:
// it only activates when a runtime CLI ("docker", "ctr", or "crictl") is found
// on PATH, all shelling out passes arguments as a vector (never a shell
// string), and any id used to build an exec argument is validated against a
// strict charset before it ever reaches exec.CommandContext. None of this is
// part of the deterministic detection core; it is a best-effort enrichment
// step that maps a raw cgroup path (as read from /proc/<pid>/cgroup) to
// container metadata (ContainerInfo) so a Process/Event can be attributed to
// the workload it belongs to.
package runtime

import (
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"sync"
)

// containerIDRe matches a 64-character hex container/pod-sandbox id anywhere
// in a cgroup line, e.g. ".../docker-<64hex>.scope" or
// ".../cri-containerd-<64hex>". Compiled once at package init.
var containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

// parseCgroupContainerID extracts a 64-hex container id from a single cgroup
// line (as found in /proc/<pid>/cgroup). It is a pure function: given the same
// input it always returns the same output, with no I/O or global state. It
// returns "" when the line does not contain a recognizable container id (for
// example a plain user/session cgroup).
func parseCgroupContainerID(cgroupLine string) string {
	return containerIDRe.FindString(cgroupLine)
}

// inspectIDRe is the safe charset for an id we will pass to a runtime CLI's
// "inspect" subcommand. It must not begin with '-' (would be read as a flag)
// and is restricted to lowercase hex, matching how container ids/short ids are
// represented by docker/containerd/cri-o.
var inspectIDRe = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// ContainerResolver attributes cgroup lines to container metadata, caching
// results so a busy sensor does not re-exec the runtime CLI for every event
// from the same container.
type ContainerResolver struct {
	// inspect looks up a single container by id. It is a field (rather than a
	// hardcoded call) so tests can substitute a fake without shelling out.
	inspect func(id string) (ContainerInfo, error)

	mu    sync.Mutex
	cache map[string]ContainerInfo
}

// NewContainerResolver builds a resolver backed by whichever container/runtime
// CLI is first found on PATH, in order: docker, ctr, crictl. If none is found,
// the resolver still works but every lookup degrades to a stub ContainerInfo
// containing only the id (attribution without enrichment).
func NewContainerResolver() *ContainerResolver {
	var bin string
	for _, candidate := range []string{"docker", "ctr", "crictl"} {
		if _, err := exec.LookPath(candidate); err == nil {
			bin = candidate
			break
		}
	}
	if bin == "" {
		return &ContainerResolver{inspect: func(id string) (ContainerInfo, error) {
			return ContainerInfo{ID: id}, nil
		}}
	}
	return &ContainerResolver{inspect: cliInspector(bin)}
}

// cliInspector returns an inspect function that shells out to bin ("docker",
// "ctr", or "crictl") to fetch container metadata. The id is validated against
// inspectIDRe before it is ever placed on the exec argument vector — invalid
// ids never reach exec.CommandContext, so there is no argument-injection
// surface. Parsing of the returned JSON is best-effort: on any failure to
// decode the runtime's own output shape, the function still fills in what it
// knows (ID) and returns a nil error, since the id itself is a valid
// attribution even without enrichment.
func cliInspector(bin string) func(id string) (ContainerInfo, error) {
	return func(id string) (ContainerInfo, error) {
		if !inspectIDRe.MatchString(id) {
			return ContainerInfo{}, errInvalidID
		}
		cmd := exec.CommandContext(context.Background(), bin, "inspect", "--format", "{{json .}}", id)
		out, err := cmd.Output()
		if err != nil {
			return ContainerInfo{ID: id}, nil
		}
		info := ContainerInfo{ID: id, Runtime: bin}
		var raw struct {
			Name  string `json:"Name"`
			Image string `json:"Image"`
			State struct {
				Running bool `json:"Running"`
			} `json:"State"`
			HostConfig struct {
				Privileged bool `json:"Privileged"`
			} `json:"HostConfig"`
			Config struct {
				Image string `json:"Image"`
			} `json:"Config"`
		}
		if json.Unmarshal(out, &raw) == nil {
			info.Name = raw.Name
			info.Privileged = raw.HostConfig.Privileged
			if raw.Config.Image != "" {
				info.ImageRef = raw.Config.Image
			} else {
				info.ImageRef = raw.Image
			}
		}
		return info, nil
	}
}

// errInvalidID is returned by the CLI-backed inspector when an id fails the
// charset guard, so it is never placed on an exec argument vector.
var errInvalidID = &idError{}

type idError struct{}

func (*idError) Error() string { return "runtime: refusing unsafe container id" }

// ByCgroup attributes a single /proc/<pid>/cgroup line to container metadata.
// The bool result reports whether the line was attributed to a container id at
// all (regardless of whether enrichment via inspect succeeded); ok is false
// only when the line contains no recognizable container id.
func (r *ContainerResolver) ByCgroup(cgroupLine string) (ContainerInfo, bool) {
	id := parseCgroupContainerID(cgroupLine)
	if id == "" {
		return ContainerInfo{}, false
	}

	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[string]ContainerInfo)
	}
	if info, ok := r.cache[id]; ok {
		r.mu.Unlock()
		return info, true
	}
	r.mu.Unlock()

	info, err := r.inspect(id)
	if err != nil {
		info = ContainerInfo{ID: id}
	}

	r.mu.Lock()
	r.cache[id] = info
	r.mu.Unlock()

	return info, true
}

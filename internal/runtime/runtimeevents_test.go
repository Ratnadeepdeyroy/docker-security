package runtime

import "testing"

func TestParseCgroupContainerID(t *testing.T) {
	const id = "3f7a1c2b9d8e4f60a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718"
	cases := map[string]string{
		"0::/system.slice/docker-" + id + ".scope":                id,
		"12:pids:/kubepods/besteffort/pod-x/cri-containerd-" + id: id,
		"0::/user.slice/user-1000.slice/session-2.scope":          "",
	}
	for in, want := range cases {
		if got := parseCgroupContainerID(in); got != want {
			t.Errorf("parseCgroupContainerID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContainerResolverCachesInspect(t *testing.T) {
	const id = "3f7a1c2b9d8e4f60a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718"
	calls := 0
	r := &ContainerResolver{inspect: func(gotID string) (ContainerInfo, error) {
		calls++
		return ContainerInfo{ID: gotID, Name: "web", ImageRef: "nginx:1"}, nil
	}}
	// note: the resolver must lazily init its cache map if nil, OR expose a constructor for tests.
	info, ok := r.ByCgroup("0::/system.slice/docker-" + id + ".scope")
	if !ok || info.Name != "web" {
		t.Fatalf("ByCgroup miss: %+v ok=%v", info, ok)
	}
	if _, ok := r.ByCgroup("0::/system.slice/docker-" + id + ".scope"); !ok {
		t.Fatalf("second ByCgroup should also attribute")
	}
	if calls != 1 {
		t.Fatalf("inspect called %d times, want 1 (cache miss then hit)", calls)
	}
}

func TestContainerResolverNoContainer(t *testing.T) {
	r := NewContainerResolver()
	if _, ok := r.ByCgroup("0::/user.slice/user-1000.slice/session-2.scope"); ok {
		t.Fatalf("non-container cgroup must not attribute")
	}
}

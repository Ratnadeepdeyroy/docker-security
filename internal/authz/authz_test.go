package authz

import "testing"

func createBody(hostConfig string) []byte {
	return []byte(`{"Image":"x","HostConfig":` + hostConfig + `}`)
}

func TestAllowByDefault(t *testing.T) {
	p := &Policy{} // empty policy: no-op plugin
	d := p.Evaluate(Request{Method: "POST", URI: "/v1.43/containers/create", Body: createBody(`{"Privileged":true}`)})
	if !d.Allow {
		t.Errorf("empty policy should allow everything, denied: %s", d.Reason)
	}
}

func TestDenyPrivileged(t *testing.T) {
	p := &Policy{DenyPrivileged: true}
	d := p.Evaluate(Request{Method: "POST", URI: "/v1.43/containers/create", Body: createBody(`{"Privileged":true}`)})
	if d.Allow || d.Rule != "AUTHZ-PRIVILEGED" {
		t.Fatalf("privileged create should be denied, got %+v", d)
	}
	// A non-privileged create passes.
	ok := p.Evaluate(Request{Method: "POST", URI: "/v1.43/containers/create", Body: createBody(`{"Privileged":false}`)})
	if !ok.Allow {
		t.Errorf("non-privileged create should be allowed, got %+v", ok)
	}
}

func TestDenyHostNamespaces(t *testing.T) {
	p := &Policy{DenyHostNamespaces: true}
	for _, mode := range []string{`{"NetworkMode":"host"}`, `{"PidMode":"host"}`, `{"IpcMode":"host"}`, `{"UTSMode":"host"}`} {
		d := p.Evaluate(Request{Method: "POST", URI: "/containers/create", Body: createBody(mode)})
		if d.Allow || d.Rule != "AUTHZ-HOSTNS" {
			t.Errorf("host namespace %s should be denied, got %+v", mode, d)
		}
	}
}

func TestDenyDockerSocketMount(t *testing.T) {
	p := &Policy{DenyDockerSocketMount: true}
	// Via Binds.
	d := p.Evaluate(Request{Method: "POST", URI: "/containers/create",
		Body: createBody(`{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}`)})
	if d.Allow || d.Rule != "AUTHZ-DOCKERSOCK" {
		t.Fatalf("docker.sock bind should be denied, got %+v", d)
	}
	// Via Mounts.
	d2 := p.Evaluate(Request{Method: "POST", URI: "/containers/create",
		Body: createBody(`{"Mounts":[{"Source":"/run/docker.sock","Type":"bind"}]}`)})
	if d2.Allow {
		t.Errorf("docker.sock mount should be denied, got %+v", d2)
	}
}

func TestDenyHostPathMounts(t *testing.T) {
	p := &Policy{DenyHostPathMounts: true}
	d := p.Evaluate(Request{Method: "POST", URI: "/containers/create",
		Body: createBody(`{"Binds":["/etc/shadow:/x"]}`)})
	if d.Allow || d.Rule != "AUTHZ-HOSTPATH" {
		t.Fatalf("sensitive host-path bind should be denied, got %+v", d)
	}
	// A benign app volume is allowed.
	ok := p.Evaluate(Request{Method: "POST", URI: "/containers/create",
		Body: createBody(`{"Binds":["/opt/appdata:/data"]}`)})
	if !ok.Allow {
		t.Errorf("benign bind should be allowed, got %+v", ok)
	}
}

func TestDenyCapAdd(t *testing.T) {
	p := &Policy{DenyCapAdd: []string{"SYS_ADMIN"}}
	// With and without the CAP_ prefix must both be caught.
	for _, cap := range []string{`["SYS_ADMIN"]`, `["CAP_SYS_ADMIN"]`, `["sys_admin"]`} {
		d := p.Evaluate(Request{Method: "POST", URI: "/containers/create", Body: createBody(`{"CapAdd":` + cap + `}`)})
		if d.Allow || d.Rule != "AUTHZ-CAPADD" {
			t.Errorf("CapAdd %s should be denied, got %+v", cap, d)
		}
	}
	ok := p.Evaluate(Request{Method: "POST", URI: "/containers/create", Body: createBody(`{"CapAdd":["NET_BIND_SERVICE"]}`)})
	if !ok.Allow {
		t.Errorf("allowed capability should pass, got %+v", ok)
	}
}

func TestReadOnlyMode(t *testing.T) {
	p := &Policy{ReadOnly: true}
	if d := p.Evaluate(Request{Method: "POST", URI: "/containers/create"}); d.Allow {
		t.Errorf("read-only mode should deny POST, got %+v", d)
	}
	if d := p.Evaluate(Request{Method: "DELETE", URI: "/containers/abc"}); d.Allow {
		t.Errorf("read-only mode should deny DELETE, got %+v", d)
	}
	if d := p.Evaluate(Request{Method: "GET", URI: "/containers/json"}); !d.Allow {
		t.Errorf("read-only mode should allow GET, got %+v", d)
	}
}

func TestNonCreateEndpointsUninspected(t *testing.T) {
	// A privileged-deny policy must not accidentally block unrelated calls.
	p := &Policy{DenyPrivileged: true}
	if d := p.Evaluate(Request{Method: "GET", URI: "/v1.43/images/json"}); !d.Allow {
		t.Errorf("listing images should be allowed, got %+v", d)
	}
}

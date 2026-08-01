package admission

import (
	"encoding/json"
	"testing"
)

func TestParseImageRef(t *testing.T) {
	cases := []struct {
		ref                 string
		reg, repo, tag, dig string
	}{
		{"nginx", "docker.io", "nginx", "", ""},
		{"nginx:1.25", "docker.io", "nginx", "1.25", ""},
		{"library/nginx:1.25", "docker.io", "library/nginx", "1.25", ""},
		{"gcr.io/proj/app:v2", "gcr.io", "proj/app", "v2", ""},
		{"localhost:5000/app", "localhost:5000", "app", "", ""},
		{"registry.internal.example.com/team/app@sha256:abcd", "registry.internal.example.com", "team/app", "", "sha256:abcd"},
	}
	for _, c := range cases {
		got := parseImageRef(c.ref)
		if got.Registry != c.reg || got.Repository != c.repo || got.Tag != c.tag || got.Digest != c.dig {
			t.Errorf("parseImageRef(%q) = reg=%q repo=%q tag=%q dig=%q; want reg=%q repo=%q tag=%q dig=%q",
				c.ref, got.Registry, got.Repository, got.Tag, got.Digest, c.reg, c.repo, c.tag, c.dig)
		}
	}
}

func TestExtractWorkloadPodFlags(t *testing.T) {
	raw := json.RawMessage(`{
		"kind":"Pod",
		"spec":{
			"hostPID": true,
			"containers":[{"name":"a","image":"docker.io/x/y:1","securityContext":{"privileged":true,"capabilities":{"add":["NET_ADMIN"]}}}],
			"volumes":[{"name":"h","hostPath":{"path":"/"}}]
		}
	}`)
	info, err := extractWorkload(raw)
	if err != nil {
		t.Fatalf("extractWorkload: %v", err)
	}
	w := info.workload
	if !w.Present || !w.Privileged || !w.RunAsRoot || !w.UsesHostPath || !w.HostPID {
		t.Fatalf("unexpected workload flags: %+v", w)
	}
	if len(w.Capabilities) != 1 || w.Capabilities[0] != "NET_ADMIN" {
		t.Fatalf("capabilities = %v", w.Capabilities)
	}
	if len(info.images) != 1 || info.images[0] != "docker.io/x/y:1" {
		t.Fatalf("images = %v", info.images)
	}
}

func TestExtractWorkloadNonRootGuarantee(t *testing.T) {
	// runAsNonRoot true at the container must clear RunAsRoot.
	raw := json.RawMessage(`{"kind":"Pod","spec":{"containers":[{"name":"a","image":"i","securityContext":{"runAsNonRoot":true}}]}}`)
	info, _ := extractWorkload(raw)
	if info.workload.RunAsRoot {
		t.Fatal("container with runAsNonRoot:true must not be flagged root")
	}

	// A non-zero runAsUser at the pod level also guarantees non-root.
	raw = json.RawMessage(`{"kind":"Pod","spec":{"securityContext":{"runAsUser":1000},"containers":[{"name":"a","image":"i"}]}}`)
	info, _ = extractWorkload(raw)
	if info.workload.RunAsRoot {
		t.Fatal("pod runAsUser:1000 must not be flagged root")
	}
}

func TestExtractWorkloadCronJobTemplate(t *testing.T) {
	raw := json.RawMessage(`{"kind":"CronJob","spec":{"jobTemplate":{"spec":{"template":{"spec":{
		"containers":[{"name":"c","image":"batch:1","securityContext":{"privileged":true}}]
	}}}}}}`)
	info, err := extractWorkload(raw)
	if err != nil {
		t.Fatalf("extractWorkload: %v", err)
	}
	if !info.workload.Present || !info.workload.Privileged {
		t.Fatalf("CronJob pod template not extracted: %+v", info.workload)
	}
}

func TestExtractWorkloadMalformed(t *testing.T) {
	if _, err := extractWorkload(json.RawMessage(`{not json`)); err == nil {
		t.Fatal("expected error on malformed object")
	}
	// An unknown kind is not an error — there is simply nothing to gate.
	info, err := extractWorkload(json.RawMessage(`{"kind":"ConfigMap","spec":{}}`))
	if err != nil || info.workload.Present {
		t.Fatalf("unknown kind should yield a not-present workload, got %+v err=%v", info.workload, err)
	}
}

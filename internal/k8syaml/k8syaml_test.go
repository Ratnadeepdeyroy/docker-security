package k8syaml

import (
	"encoding/json"
	"reflect"
	"testing"
)

// parseOne is a helper: split, take the first doc, convert to a generic value.
func parseOne(t *testing.T, src string) map[string]any {
	t.Helper()
	docs := SplitDocuments(src)
	if len(docs) == 0 {
		t.Fatal("no documents parsed")
	}
	data, err := ToJSON(docs[0])
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal result: %v (json=%s)", err, data)
	}
	return m
}

func TestScalarsAndTypes(t *testing.T) {
	m := parseOne(t, `
apiVersion: v1
kind: Pod
replicas: 3
enabled: true
disabled: false
empty: null
name: "quoted value"
`)
	if m["apiVersion"] != "v1" || m["kind"] != "Pod" {
		t.Errorf("string scalars wrong: %+v", m)
	}
	if m["replicas"].(float64) != 3 {
		t.Errorf("int scalar wrong: %v", m["replicas"])
	}
	if m["enabled"] != true || m["disabled"] != false {
		t.Errorf("bool scalars wrong: %+v", m)
	}
	if m["empty"] != nil {
		t.Errorf("null scalar wrong: %v", m["empty"])
	}
	if m["name"] != "quoted value" {
		t.Errorf("quoted scalar wrong: %v", m["name"])
	}
}

func TestNestedMapping(t *testing.T) {
	m := parseOne(t, `
metadata:
  name: web
  namespace: prod
  labels:
    app: web
    tier: frontend
`)
	md := m["metadata"].(map[string]any)
	if md["name"] != "web" || md["namespace"] != "prod" {
		t.Errorf("nested map wrong: %+v", md)
	}
	labels := md["labels"].(map[string]any)
	if labels["app"] != "web" || labels["tier"] != "frontend" {
		t.Errorf("double-nested map wrong: %+v", labels)
	}
}

func TestSequenceOfMaps(t *testing.T) {
	m := parseOne(t, `
spec:
  containers:
  - name: app
    image: nginx:1.25
  - name: sidecar
    image: envoy
`)
	spec := m["spec"].(map[string]any)
	containers := spec["containers"].([]any)
	if len(containers) != 2 {
		t.Fatalf("want 2 containers, got %d: %+v", len(containers), containers)
	}
	c0 := containers[0].(map[string]any)
	if c0["name"] != "app" || c0["image"] != "nginx:1.25" {
		t.Errorf("first container wrong: %+v", c0)
	}
	c1 := containers[1].(map[string]any)
	if c1["name"] != "sidecar" {
		t.Errorf("second container wrong: %+v", c1)
	}
}

func TestScalarSequence(t *testing.T) {
	m := parseOne(t, `
capabilities:
  drop:
  - ALL
  add:
  - NET_ADMIN
  - SYS_ADMIN
`)
	caps := m["capabilities"].(map[string]any)
	drop := caps["drop"].([]any)
	if len(drop) != 1 || drop[0] != "ALL" {
		t.Errorf("drop seq wrong: %+v", drop)
	}
	add := caps["add"].([]any)
	if len(add) != 2 || add[0] != "NET_ADMIN" || add[1] != "SYS_ADMIN" {
		t.Errorf("add seq wrong: %+v", add)
	}
}

func TestDeepSecurityContext(t *testing.T) {
	// This is the exact shape the harden Workload parser needs to read.
	m := parseOne(t, `
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
      runAsNonRoot: false
      capabilities:
        add:
        - SYS_ADMIN
`)
	spec := m["spec"].(map[string]any)
	c := spec["containers"].([]any)[0].(map[string]any)
	sc := c["securityContext"].(map[string]any)
	if sc["privileged"] != true {
		t.Errorf("privileged not parsed: %+v", sc)
	}
	caps := sc["capabilities"].(map[string]any)["add"].([]any)
	if len(caps) != 1 || caps[0] != "SYS_ADMIN" {
		t.Errorf("nested caps wrong: %+v", caps)
	}
}

func TestFlowSequence(t *testing.T) {
	m := parseOne(t, `args: [--flag, value, 3]`)
	args := m["args"].([]any)
	if len(args) != 3 || args[0] != "--flag" || args[2].(float64) != 3 {
		t.Errorf("flow seq wrong: %+v", args)
	}
}

func TestMultiDocSplit(t *testing.T) {
	src := `
apiVersion: v1
kind: Pod
---
apiVersion: apps/v1
kind: Deployment
---
# only a comment
`
	docs := SplitDocuments(src)
	if len(docs) != 2 {
		t.Fatalf("want 2 real docs (comment-only dropped), got %d", len(docs))
	}
}

func TestInlineCommentStripped(t *testing.T) {
	m := parseOne(t, `image: nginx:1.25  # pinned version`)
	if m["image"] != "nginx:1.25" {
		t.Errorf("inline comment not stripped: %q", m["image"])
	}
	// A # inside a quoted value must survive.
	m2 := parseOne(t, `token: "abc#def"`)
	if m2["token"] != "abc#def" {
		t.Errorf("# inside quotes wrongly stripped: %q", m2["token"])
	}
}

func TestRoundTripsToStableJSON(t *testing.T) {
	docs := SplitDocuments("a: 1\nb:\n  c: two\n")
	data, err := ToJSON(docs[0])
	if err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	_ = json.Unmarshal(data, &got)
	_ = json.Unmarshal([]byte(`{"a":1,"b":{"c":"two"}}`), &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %s, want a:1,b.c:two", data)
	}
}

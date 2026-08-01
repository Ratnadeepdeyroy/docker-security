package registry

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestRegistry starts a MemoryRegistry on an httptest server and returns a
// Client wired to it plus the registry host. Everything is loopback and
// in-process: no external network is touched.
func newTestRegistry(t *testing.T) (*Client, string, *MemoryRegistry) {
	t.Helper()
	mem := NewMemoryRegistry()
	srv := httptest.NewServer(mem)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	client := New(WithHTTPClient(srv.Client()), WithPlainHTTP())
	return client, host, mem
}

func TestPingPushPull(t *testing.T) {
	client, host, _ := newTestRegistry(t)
	ctx := context.Background()

	if err := client.Ping(ctx, host); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// Push a config blob and a manifest referencing it, then pull the manifest
	// back by tag and confirm the digest round-trips.
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	cfgDesc, err := client.PutBlob(ctx, host, "team/app", config)
	if err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	man := Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config:        Descriptor{MediaType: MediaTypeOCIConfig, Digest: cfgDesc.Digest, Size: cfgDesc.Size},
		Layers:        []Descriptor{},
	}
	manBytes := mustMarshal(t, man)
	putDesc, err := client.PutManifest(ctx, host, "team/app", "1.0", MediaTypeOCIManifest, manBytes)
	if err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	ref := Reference{Registry: host, Repository: "team/app", Tag: "1.0"}
	rm, err := client.GetManifest(ctx, ref)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if rm.Digest != putDesc.Digest {
		t.Errorf("pulled digest %s != pushed %s", rm.Digest, putDesc.Digest)
	}
	if string(rm.Bytes) != string(manBytes) {
		t.Errorf("pulled manifest bytes differ from pushed")
	}

	// ResolveDigest via HEAD must agree.
	rd, err := client.ResolveDigest(ctx, ref)
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if rd != putDesc.Digest {
		t.Errorf("ResolveDigest = %s, want %s", rd, putDesc.Digest)
	}
}

// TestGetManifestDetectsTamperedDigest proves the client refuses content that
// does not match a digest-pinned reference — the anti-tamper guarantee.
func TestGetManifestDetectsTamperedDigest(t *testing.T) {
	client, host, mem := newTestRegistry(t)
	ctx := context.Background()

	real := []byte(`{"schemaVersion":2}`)
	realDigest := Digest(real)
	if _, err := client.PutManifest(ctx, host, "app", "v1", MediaTypeOCIManifest, real); err != nil {
		t.Fatal(err)
	}

	// Corrupt the stored manifest bytes behind the tag, keeping the same tag.
	mem.mu.Lock()
	repo := mem.repos["app"]
	repo.manifests[realDigest] = memManifest{bytes: []byte(`{"schemaVersion":2,"tampered":true}`), mediaType: MediaTypeOCIManifest}
	mem.mu.Unlock()

	// Pulling by the ORIGINAL digest must now fail the content check.
	ref := Reference{Registry: host, Repository: "app", Digest: realDigest}
	if _, err := client.GetManifest(ctx, ref); err == nil {
		t.Fatal("GetManifest accepted content that does not match the pinned digest")
	}
}

func TestListTags(t *testing.T) {
	client, host, _ := newTestRegistry(t)
	ctx := context.Background()
	for _, tag := range []string{"v2", "v1", "latest"} {
		if _, err := client.PutManifest(ctx, host, "app", tag, MediaTypeOCIManifest, []byte(`{"t":"`+tag+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	tags, err := client.ListTags(ctx, host, "app")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	// MemoryRegistry sorts tags for determinism.
	want := []string{"latest", "v1", "v2"}
	if strings.Join(tags, ",") != strings.Join(want, ",") {
		t.Errorf("tags = %v, want %v", tags, want)
	}
}

// TestAuthRequired exercises the client's behavior against a registry that
// demands authentication: without credentials it fails cleanly (no token
// endpoint), and Ping still succeeds because /v2/ is exempt.
func TestAuthRequired(t *testing.T) {
	client, host, mem := newTestRegistry(t)
	mem.SetRequireAuth(true)
	ctx := context.Background()

	if err := client.Ping(ctx, host); err != nil {
		t.Fatalf("Ping should tolerate 401: %v", err)
	}
	_, err := client.GetManifest(ctx, Reference{Registry: host, Repository: "app", Tag: "v1"})
	if err == nil {
		t.Fatal("expected auth failure pulling from an auth-required registry")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

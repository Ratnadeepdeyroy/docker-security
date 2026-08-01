package registry

import (
	"context"
	"testing"
)

// TestReferrersRoundTrip is the core supply-chain plumbing test: push an image
// manifest, attach an artifact (a stand-in signature bundle) as a referrer, then
// discover it via the referrers API and pull it back intact.
func TestReferrersRoundTrip(t *testing.T) {
	client, host, _ := newTestRegistry(t)
	ctx := context.Background()

	// Push a subject image manifest.
	subjectBytes := []byte(`{"schemaVersion":2,"mediaType":"` + MediaTypeOCIManifest + `"}`)
	subject, err := client.PutManifest(ctx, host, "app", "1.0", MediaTypeOCIManifest, subjectBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Attach a bundle as a referrer.
	const artifactType = "application/vnd.docker-security.bundle.v1+json"
	bundle := []byte(`{"bundle":"pretend-signature"}`)
	ref, err := client.PutReferrer(ctx, host, "app", subject.Digest, artifactType, bundle, map[string]string{"kind": "signature"})
	if err != nil {
		t.Fatalf("PutReferrer: %v", err)
	}

	// Discover referrers of the subject.
	idx, err := client.Referrers(ctx, host, "app", subject.Digest, "")
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("expected 1 referrer, got %d", len(idx.Manifests))
	}
	if idx.Manifests[0].ArtifactType != artifactType {
		t.Errorf("referrer artifactType = %q", idx.Manifests[0].ArtifactType)
	}
	if idx.Manifests[0].Digest != ref.Digest {
		t.Errorf("referrer digest = %s, want %s", idx.Manifests[0].Digest, ref.Digest)
	}

	// Filtering by a non-matching artifactType yields nothing.
	empty, err := client.Referrers(ctx, host, "app", subject.Digest, "application/other")
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Manifests) != 0 {
		t.Errorf("expected no referrers for wrong artifactType, got %d", len(empty.Manifests))
	}

	// Pull the referrer manifest and its bundle blob back.
	rm, err := client.GetManifest(ctx, Reference{Registry: host, Repository: "app", Digest: ref.Digest})
	if err != nil {
		t.Fatal(err)
	}
	man, err := ParseManifest(rm.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if man.Subject == nil || man.Subject.Digest != subject.Digest {
		t.Fatalf("referrer manifest subject = %+v, want %s", man.Subject, subject.Digest)
	}
	if len(man.Layers) != 1 {
		t.Fatalf("referrer manifest should carry one layer, got %d", len(man.Layers))
	}
	blob, err := client.GetBlob(ctx, host, "app", man.Layers[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != string(bundle) {
		t.Errorf("referrer bundle blob = %q, want %q", blob, bundle)
	}
}

// TestReferrersEmptyIsNotError: a subject with no referrers returns an empty
// index, so "this image is unsigned" is representable without an error.
func TestReferrersEmptyIsNotError(t *testing.T) {
	client, host, _ := newTestRegistry(t)
	ctx := context.Background()
	subjectBytes := []byte(`{"schemaVersion":2}`)
	subject, _ := client.PutManifest(ctx, host, "app", "1.0", MediaTypeOCIManifest, subjectBytes)

	idx, err := client.Referrers(ctx, host, "app", subject.Digest, "")
	if err != nil {
		t.Fatalf("Referrers on unsigned subject: %v", err)
	}
	if len(idx.Manifests) != 0 {
		t.Errorf("expected no referrers, got %d", len(idx.Manifests))
	}
}

func TestReferrerTagMapping(t *testing.T) {
	got := referrerTag("sha256:abc123")
	if got != "sha256-abc123" {
		t.Errorf("referrerTag = %q, want sha256-abc123", got)
	}
}

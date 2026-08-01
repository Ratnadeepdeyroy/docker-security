package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// --- OCI 1.1 referrers ------------------------------------------------------
//
// Referrers are how signatures and attestations attach to an image without
// mutating the image: a referrer is a manifest whose `subject` field points at
// the image's manifest digest. The registry indexes these and answers
// GET /v2/<name>/referrers/<digest> with an index of everything referring to
// that digest. Registries that predate OCI 1.1 don't have the endpoint, so the
// spec defines a fallback: a manifest tagged `sha256-<hex>` that holds the
// index. We implement both — the API path first, the tag fallback on 404 — so
// verification works against old and new registries alike.

// referrerTag maps a subject digest to its fallback referrers tag per the OCI
// spec: "sha256:abc" -> "sha256-abc".
func referrerTag(subjectDigest string) string {
	return strings.Replace(subjectDigest, ":", "-", 1)
}

// Referrers returns the manifests that refer to subjectDigest, optionally
// filtered to a single artifactType. It tries the referrers API and falls back
// to the tag scheme. A subject with no referrers yields an empty index, not an
// error — "nothing is signed" is a valid, and security-relevant, answer.
func (c *Client) Referrers(ctx context.Context, registry, repo, subjectDigest, artifactType string) (*Index, error) {
	if err := validateDigest(subjectDigest); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/%s/referrers/%s", c.baseURL(registry), repo, subjectDigest)
	if artifactType != "" {
		url += "?artifactType=" + artifactType
	}
	resp, err := c.do(ctx, http.MethodGet, url, MediaTypeOCIIndex, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		idx, err := decodeIndex(resp)
		if err != nil {
			return nil, err
		}
		return filterByArtifactType(idx, artifactType), nil
	case http.StatusNotFound:
		// Fall back to the tag scheme.
		return c.referrersByTag(ctx, registry, repo, subjectDigest, artifactType)
	default:
		return nil, statusError("referrers", resp)
	}
}

// referrersByTag implements the OCI fallback: fetch the manifest tagged
// sha256-<hex> and treat it as the referrers index.
func (c *Client) referrersByTag(ctx context.Context, registry, repo, subjectDigest, artifactType string) (*Index, error) {
	ref := Reference{Registry: registry, Repository: repo, Tag: referrerTag(subjectDigest)}
	rm, err := c.GetManifest(ctx, ref)
	if err != nil {
		// No fallback tag either: genuinely no referrers.
		return &Index{SchemaVersion: 2, MediaType: MediaTypeOCIIndex}, nil
	}
	idx, err := ParseIndex(rm.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse fallback referrers index: %w", err)
	}
	return filterByArtifactType(idx, artifactType), nil
}

// PutReferrer attaches an artifact (e.g. a signature/attestation bundle) to a
// subject digest. It uploads the artifact blob and an OCI manifest whose
// `subject` is the target image, then also writes the fallback referrers tag so
// registries without native support still resolve it. Returns the referrer
// manifest's descriptor.
func (c *Client) PutReferrer(ctx context.Context, registry, repo, subjectDigest, artifactType string, artifact []byte, annotations map[string]string) (Descriptor, error) {
	if err := validateDigest(subjectDigest); err != nil {
		return Descriptor{}, err
	}
	// Upload the artifact as a layer blob and an empty config blob.
	layer, err := c.PutBlob(ctx, registry, repo, artifact)
	if err != nil {
		return Descriptor{}, fmt.Errorf("upload referrer artifact: %w", err)
	}
	layer.MediaType = artifactType
	emptyConfig := []byte("{}")
	cfg, err := c.PutBlob(ctx, registry, repo, emptyConfig)
	if err != nil {
		return Descriptor{}, fmt.Errorf("upload referrer config: %w", err)
	}
	cfg.MediaType = MediaTypeEmptyJSON

	man := Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		ArtifactType:  artifactType,
		Config:        cfg,
		Layers:        []Descriptor{layer},
		Subject:       &Descriptor{MediaType: MediaTypeOCIManifest, Digest: subjectDigest},
		Annotations:   annotations,
	}
	manBytes, err := json.Marshal(man)
	if err != nil {
		return Descriptor{}, fmt.Errorf("marshal referrer manifest: %w", err)
	}
	manDigest := Digest(manBytes)

	// Push the referrer manifest by its own digest.
	desc, err := c.PutManifest(ctx, registry, repo, manDigest, MediaTypeOCIManifest, manBytes)
	if err != nil {
		return Descriptor{}, err
	}
	desc.ArtifactType = artifactType
	desc.Annotations = annotations
	return desc, nil
}

func decodeIndex(resp *http.Response) (*Index, error) {
	var idx Index
	if err := json.NewDecoder(resp.Body).Decode(&idx); err != nil {
		return nil, fmt.Errorf("decode referrers index: %w", err)
	}
	return &idx, nil
}

// filterByArtifactType narrows an index to descriptors of a given artifactType.
// An empty filter passes everything.
func filterByArtifactType(idx *Index, artifactType string) *Index {
	if artifactType == "" {
		return idx
	}
	out := &Index{SchemaVersion: idx.SchemaVersion, MediaType: idx.MediaType}
	for _, d := range idx.Manifests {
		if d.ArtifactType == artifactType {
			out.Manifests = append(out.Manifests, d)
		}
	}
	return out
}

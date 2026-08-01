package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// --- OCI image layout -------------------------------------------------------
//
// Verification often happens against an image on disk (an OCI layout produced by
// a build) rather than a live registry. The one value the verify path needs from
// such a layout is the manifest digest — the identity a signature commits to.
// We read it straight from index.json without pulling layers, so digest
// resolution is cheap and fully offline. A docker-save tarball does not record a
// manifest digest (it references the config by filename), so callers that only
// have a docker-save archive must supply the digest explicitly; that limitation
// is documented rather than papered over with a guessed digest.

// layoutIndex is the subset of index.json we read.
type layoutIndex struct {
	Manifests []layoutDescriptor `json:"manifests"`
}

type layoutDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
}

// ManifestDigestFromLayout returns the primary image manifest digest recorded in
// an OCI image layout directory's index.json. If the top-level entry is itself
// an image index, it follows one level to the first image manifest. It does not
// verify layer content — only the digest identity the layout advertises.
func ManifestDigestFromLayout(dir string) (string, error) {
	idxBytes, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return "", fmt.Errorf("read oci layout index: %w", err)
	}
	var idx layoutIndex
	if err := json.Unmarshal(idxBytes, &idx); err != nil {
		return "", fmt.Errorf("parse oci layout index: %w", err)
	}
	if len(idx.Manifests) == 0 {
		return "", fmt.Errorf("oci layout index has no manifests")
	}
	top := idx.Manifests[0]
	if err := validateDigest(top.Digest); err != nil {
		return "", fmt.Errorf("oci layout index digest: %w", err)
	}
	// If the top descriptor is a multi-arch index, descend one level to a
	// concrete image manifest so the digest we return is one a signature would
	// actually target.
	if IsIndex(top.MediaType) {
		inner, err := readLayoutBlob(dir, top.Digest)
		if err == nil {
			var childIdx layoutIndex
			if json.Unmarshal(inner, &childIdx) == nil && len(childIdx.Manifests) > 0 {
				if err := validateDigest(childIdx.Manifests[0].Digest); err == nil {
					return childIdx.Manifests[0].Digest, nil
				}
			}
		}
	}
	return top.Digest, nil
}

// readLayoutBlob reads a blob from an OCI layout's blobs/sha256/<hex> path.
func readLayoutBlob(dir, digest string) ([]byte, error) {
	alg, hexPart, ok := splitOnce(digest, ':')
	if !ok {
		return nil, fmt.Errorf("bad digest %q", digest)
	}
	return os.ReadFile(filepath.Join(dir, "blobs", alg, hexPart))
}

func splitOnce(s string, sep byte) (a, b string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

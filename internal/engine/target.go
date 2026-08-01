// Package engine is the core of docker-security: it defines the analysis Target,
// the Finding/Report model, the Module plugin interface, and the Engine that
// runs registered modules against a Target. Frontends (CLI, HTTP, connectors)
// and capability modules both depend only on this package.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// TargetType identifies what kind of artifact is being analyzed.
type TargetType string

const (
	TargetDockerfile TargetType = "dockerfile"
	TargetImage      TargetType = "image"
	TargetFilesystem TargetType = "filesystem"
	TargetContainer  TargetType = "container"
	TargetRegistry   TargetType = "registry"
)

// Target is the subject of an analysis run.
type Target struct {
	Type TargetType `json:"type"`
	// Location is a filesystem path, image reference, or container id,
	// depending on Type.
	Location string `json:"location"`
	// Content holds inlined bytes (e.g. Dockerfile contents) when the caller
	// has already loaded them. Modules should prefer Content when present.
	Content  []byte            `json:"-"`
	Metadata map[string]string `json:"metadata,omitempty"`

	// imageOnce/imageCached/imageErr memoize Image() so an image target's
	// archive is decompressed at most once per scan, no matter how many
	// modules ask for it. A Target is scan-scoped (one Target = one Run), so
	// this cache's lifetime matches a single scan; sync.Once also makes it
	// safe if a Target were ever shared across goroutines.
	imageOnce   sync.Once
	imageCached *oci.Image
	imageErr    error
}

// Image lazily loads and caches the target's *oci.Image, decompressing
// Location at most once regardless of how many callers invoke Image() during
// a scan. Every caller observes the same loaded image (and the same error, if
// loading failed); callers must treat the returned *oci.Image as read-only
// since it is shared. It is the caller's responsibility to only call Image()
// for an image-bearing Target (e.g. Type == TargetImage).
func (t *Target) Image() (*oci.Image, error) {
	t.imageOnce.Do(func() {
		t.imageCached, t.imageErr = oci.Load(t.Location)
	})
	return t.imageCached, t.imageErr
}

// NewDockerfileTarget loads a Dockerfile from disk.
func NewDockerfileTarget(path string) (*Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dockerfile %q: %w", path, err)
	}
	return &Target{
		Type:     TargetDockerfile,
		Location: path,
		Content:  data,
		Metadata: map[string]string{},
	}, nil
}

// DetectType makes a best-effort guess of the target type from a reference
// string: a Dockerfile path, an image archive/layout, some other filesystem
// path, or an image ref.
func DetectType(ref string) TargetType {
	base := strings.ToLower(filepath.Base(ref))
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return TargetDockerfile
	}
	info, err := os.Stat(ref)
	if err != nil {
		// Not a path on disk: assume it names an image in a registry.
		return TargetImage
	}
	if info.IsDir() {
		// A directory carrying OCI-layout markers is an image, not a tree.
		for _, marker := range []string{"oci-layout", "index.json"} {
			if _, err := os.Stat(filepath.Join(ref, marker)); err == nil {
				return TargetImage
			}
		}
		return TargetFilesystem
	}
	// A regular file with an image-archive extension is a saved image.
	if isImageArchive(base) {
		return TargetImage
	}
	return TargetFilesystem
}

// isImageArchive reports whether a filename looks like a saved image tarball.
func isImageArchive(base string) bool {
	for _, ext := range []string{".tar", ".tar.gz", ".tgz", ".oci"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

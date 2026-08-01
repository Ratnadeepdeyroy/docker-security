// Package oci loads container images into flat file trees that catalogers can
// walk. It reads two on-disk shapes without any registry access: a `docker
// save` tarball (manifest.json + layer tars) and an OCI image layout (an
// `oci-layout`/`index.json`/`blobs` directory, or that same layout inside a
// tar). Layers are applied in order with whiteout semantics so the result is
// the image's effective filesystem. It re-implements only what it needs from
// the OCI spec; it does not depend on any container tooling.
package oci

import (
	"io/fs"
	"path"
	"sort"
	"strings"
)

// File is a regular file extracted from an image layer or a filesystem.
type File struct {
	// Path is a slash-separated path relative to the tree root, with no
	// leading slash (e.g. "var/lib/dpkg/status").
	Path string
	Mode fs.FileMode
	Size int64
	// Data holds the full file contents. Images are loaded into memory; this
	// is fine for the small fixtures the tool is tested against and keeps
	// catalogers simple. Large-image streaming is a later concern.
	Data []byte
}

// Layer is one image layer: the raw set of entries it introduced, before any
// whiteouts from later layers are applied. Keeping per-layer files available
// lets later capabilities (e.g. secret scanning) inspect deleted content.
type Layer struct {
	Index  int
	Digest string
	Files  []*File
	// Whiteouts lists whiteout markers this layer carried, as cleaned paths of
	// the deleted target (opaque markers keep their ".wh..wh..opq" basename).
	Whiteouts []string
}

// Image is a loaded container image.
type Image struct {
	// RepoTags are the "name:tag" references recorded for the image, if any.
	RepoTags []string
	// ConfigDigest is the sha256 digest of the image config blob (e.g.
	// "sha256:abc..."), or "" if unknown.
	ConfigDigest string
	// Config is the raw image config JSON.
	Config []byte
	Layers []*Layer
}

// FileTree is the flattened, effective filesystem of an image (or a scanned
// directory): the union of all layers with whiteouts applied.
type FileTree struct {
	files map[string]*File
}

// newFileTree returns an empty tree.
func newFileTree() *FileTree { return &FileTree{files: map[string]*File{}} }

// TreeFromMap builds a FileTree from a path -> contents map. Paths are
// normalized (leading slashes and "./" stripped). It is a convenience for
// callers that already hold file contents in memory, and for tests.
func TreeFromMap(files map[string][]byte) *FileTree {
	t := newFileTree()
	for p, data := range files {
		cp := cleanPath(p)
		if cp == "" {
			continue
		}
		t.files[cp] = &File{Path: cp, Mode: 0o644, Size: int64(len(data)), Data: data}
	}
	return t
}

// Get returns the file at path (with or without a leading slash) if present.
func (t *FileTree) Get(p string) (*File, bool) {
	f, ok := t.files[cleanPath(p)]
	return f, ok
}

// Files returns every file in the tree sorted by path, for deterministic
// walking by catalogers.
func (t *FileTree) Files() []*File {
	out := make([]*File, 0, len(t.files))
	for _, f := range t.files {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Flatten collapses the image's layers into a single FileTree, applying
// whiteouts and opaque-directory markers in layer order.
func (img *Image) Flatten() *FileTree {
	t := newFileTree()
	for _, layer := range img.Layers {
		// Pass 1: apply this layer's whiteouts against the lower layers.
		for _, e := range layer.Files {
			base := path.Base(e.Path)
			if base == whiteoutOpaque {
				t.removePrefix(path.Dir(e.Path))
				continue
			}
			if strings.HasPrefix(base, whiteoutPrefix) {
				target := path.Join(path.Dir(e.Path), strings.TrimPrefix(base, whiteoutPrefix))
				t.remove(target)
			}
		}
		// Pass 2: add this layer's regular files.
		for _, e := range layer.Files {
			base := path.Base(e.Path)
			if base == whiteoutOpaque || strings.HasPrefix(base, whiteoutPrefix) {
				continue
			}
			cp := cleanPath(e.Path)
			if cp == "" {
				continue
			}
			f := *e
			f.Path = cp
			t.files[cp] = &f
		}
	}
	return t
}

const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// remove deletes a path and, if it names a directory, everything beneath it.
func (t *FileTree) remove(p string) {
	p = cleanPath(p)
	delete(t.files, p)
	t.removePrefix(p)
}

// removePrefix deletes every file whose path lies under dir.
func (t *FileTree) removePrefix(dir string) {
	dir = cleanPath(dir)
	prefix := dir + "/"
	if dir == "" {
		prefix = ""
	}
	for k := range t.files {
		if prefix == "" || strings.HasPrefix(k, prefix) {
			delete(t.files, k)
		}
	}
}

// cleanPath normalizes a tar/OS path to a slash path with no leading slash or
// "./" prefix. It returns "" for the root or empty input.
func cleanPath(p string) string {
	p = strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(p, "\\", "/")), "/")
	return p
}

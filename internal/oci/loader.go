package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// maxFileBytes caps how large a single extracted file may be, guarding against
// decompression bombs in untrusted images. Package-DB and metadata files are
// far smaller than this.
const maxFileBytes = 256 << 20 // 256 MiB

// Load reads an image from a path. The path may be a `docker save` tarball, an
// OCI-layout tarball, or an OCI-layout directory.
func Load(p string) (*Image, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", p, err)
	}
	if info.IsDir() {
		return loadOCIDir(p)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", p, err)
	}
	entries, err := readTarEntries(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read image tar %q: %w", p, err)
	}
	if _, ok := entries["manifest.json"]; ok {
		return loadDockerSave(entries)
	}
	if _, ok := entries["index.json"]; ok {
		return loadOCIEntries(entries)
	}
	return nil, fmt.Errorf("%q is neither a docker-save nor an OCI-layout archive (no manifest.json or index.json)", p)
}

// blobStore resolves image blobs by reference, abstracting over a docker-save
// tar (arbitrary paths) and an OCI layout (blobs/sha256/<hex> or a "sha256:..."
// digest).
type blobStore struct {
	entries map[string][]byte
	// dir, if set, resolves blobs from an on-disk OCI layout directory.
	dir string
}

func (b blobStore) get(ref string) ([]byte, error) {
	// Normalize an OCI digest reference to its blob path.
	rel := ref
	if strings.HasPrefix(ref, "sha256:") {
		rel = path.Join("blobs", "sha256", strings.TrimPrefix(ref, "sha256:"))
	}
	rel = cleanPath(rel)
	if b.entries != nil {
		if data, ok := b.entries[rel]; ok {
			return data, nil
		}
		return nil, fmt.Errorf("blob %q not found in archive", ref)
	}
	data, err := os.ReadFile(filepath.Join(b.dir, filepath.FromSlash(rel)))
	if err != nil {
		return nil, fmt.Errorf("read blob %q: %w", ref, err)
	}
	return data, nil
}

// --- docker save -----------------------------------------------------------

type dockerManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

func loadDockerSave(entries map[string][]byte) (*Image, error) {
	var manifests []dockerManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifests); err != nil {
		return nil, fmt.Errorf("parse manifest.json: %w", err)
	}
	if len(manifests) == 0 {
		return nil, fmt.Errorf("manifest.json has no image entries")
	}
	m := manifests[0]
	store := blobStore{entries: entries}
	img := &Image{RepoTags: m.RepoTags}
	if cfg, err := store.get(m.Config); err == nil {
		img.Config = cfg
		img.ConfigDigest = digestFromRef(m.Config)
	}
	for i, lp := range m.Layers {
		data, err := store.get(lp)
		if err != nil {
			return nil, err
		}
		layer, err := layerFromTar(i, digestFromRef(lp), data)
		if err != nil {
			return nil, fmt.Errorf("layer %d (%s): %w", i, lp, err)
		}
		img.Layers = append(img.Layers, layer)
	}
	return img, nil
}

// --- OCI layout ------------------------------------------------------------

type ociIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
}

type ociManifest struct {
	Config    ociDescriptor   `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
	Manifests []ociDescriptor `json:"manifests"` // present when this is an image index
}

func loadOCIDir(dir string) (*Image, error) {
	idx, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("read index.json: %w", err)
	}
	return buildFromOCIIndex(idx, blobStore{dir: dir})
}

func loadOCIEntries(entries map[string][]byte) (*Image, error) {
	return buildFromOCIIndex(entries["index.json"], blobStore{entries: entries})
}

func buildFromOCIIndex(indexJSON []byte, store blobStore) (*Image, error) {
	var idx ociIndex
	if err := json.Unmarshal(indexJSON, &idx); err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	manifest, err := resolveManifest(idx.Manifests, store, 0)
	if err != nil {
		return nil, err
	}
	img := &Image{}
	if cfg, err := store.get(manifest.Config.Digest); err == nil {
		img.Config = cfg
		img.ConfigDigest = manifest.Config.Digest
	}
	for i, ld := range manifest.Layers {
		data, err := store.get(ld.Digest)
		if err != nil {
			return nil, err
		}
		layer, err := layerFromTar(i, ld.Digest, data)
		if err != nil {
			return nil, fmt.Errorf("layer %d (%s): %w", i, ld.Digest, err)
		}
		img.Layers = append(img.Layers, layer)
	}
	return img, nil
}

// resolveManifest walks descriptors to the first concrete image manifest,
// following one level of image-index nesting.
func resolveManifest(descs []ociDescriptor, store blobStore, depth int) (*ociManifest, error) {
	if depth > 8 {
		return nil, fmt.Errorf("image index nested too deeply")
	}
	for _, d := range descs {
		data, err := store.get(d.Digest)
		if err != nil {
			continue
		}
		var m ociManifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if len(m.Layers) > 0 {
			return &m, nil
		}
		if len(m.Manifests) > 0 {
			if inner, err := resolveManifest(m.Manifests, store, depth+1); err == nil {
				return inner, nil
			}
		}
	}
	return nil, fmt.Errorf("no image manifest with layers found in index")
}

// --- shared tar/layer plumbing ---------------------------------------------

// readTarEntries reads a tar stream into a map of cleaned path -> bytes,
// keeping only regular files.
func readTarEntries(r io.Reader) (map[string][]byte, error) {
	tr := tar.NewReader(maybeGunzip(r))
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		data, err := readCapped(tr)
		if err != nil {
			return nil, err
		}
		out[cleanPath(h.Name)] = data
	}
	return out, nil
}

// layerFromTar decodes a (possibly gzipped) layer tar into a Layer, preserving
// regular files and recording whiteout markers.
func layerFromTar(index int, digest string, data []byte) (*Layer, error) {
	tr := tar.NewReader(maybeGunzip(bytes.NewReader(data)))
	layer := &Layer{Index: index, Digest: digest}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := cleanPath(h.Name)
		if name == "" {
			continue
		}
		base := path.Base(name)
		if base == whiteoutOpaque || strings.HasPrefix(base, whiteoutPrefix) {
			layer.Whiteouts = append(layer.Whiteouts, name)
			// Keep the marker in Files so Flatten can act on it, but with no
			// data payload.
			layer.Files = append(layer.Files, &File{Path: name, Mode: fs.FileMode(h.Mode)})
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		body, err := readCapped(tr)
		if err != nil {
			return nil, err
		}
		layer.Files = append(layer.Files, &File{
			Path: name,
			Mode: fs.FileMode(h.Mode),
			Size: h.Size,
			Data: body,
		})
	}
	return layer, nil
}

// maybeGunzip transparently decompresses r if it begins with the gzip magic.
func maybeGunzip(r io.Reader) io.Reader {
	br := bufReader(r)
	magic, _ := br.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		if zr, err := gzip.NewReader(br); err == nil {
			return zr
		}
	}
	return br
}

func readCapped(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxFileBytes))
}

// digestFromRef extracts a "sha256:hex" digest from a blob reference such as
// "blobs/sha256/hex" or "hex.json"; falls back to the raw reference.
func digestFromRef(ref string) string {
	ref = cleanPath(ref)
	if strings.HasPrefix(ref, "sha256:") {
		return ref
	}
	if i := strings.Index(ref, "sha256/"); i >= 0 {
		return "sha256:" + strings.TrimSuffix(ref[i+len("sha256/"):], ".json")
	}
	return ref
}

// TreeFromDir walks an on-disk directory into a FileTree, as if it were a
// flattened image root. Symlinks are skipped; only regular files are read.
func TreeFromDir(dir string) (*FileTree, error) {
	t := newFileTree()
	root := filepath.Clean(dir)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxFileBytes {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		cp := cleanPath(rel)
		t.files[cp] = &File{Path: cp, Mode: info.Mode(), Size: info.Size(), Data: data}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// bufReader wraps r in a peekable reader.
func bufReader(r io.Reader) *peeker { return &peeker{r: r} }

// peeker is a tiny buffered reader supporting a 2-byte Peek, avoiding a
// dependency on bufio's larger surface while still allowing gzip sniffing.
type peeker struct {
	r   io.Reader
	buf []byte
}

func (p *peeker) Peek(n int) ([]byte, error) {
	for len(p.buf) < n {
		tmp := make([]byte, n-len(p.buf))
		m, err := p.r.Read(tmp)
		p.buf = append(p.buf, tmp[:m]...)
		if err != nil {
			return p.buf, err
		}
	}
	return p.buf[:n], nil
}

func (p *peeker) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}

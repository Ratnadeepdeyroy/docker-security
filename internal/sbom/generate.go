package sbom

import (
	"context"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// Generate builds an SBOM from an analysis target. It supports image targets
// (a `docker save` archive, an OCI-layout archive, or an OCI-layout directory
// at Target.Location) and filesystem targets (a directory at Target.Location).
// The operation is fully offline and deterministic. A cataloger that fails on a
// single ecosystem contributes a warning rather than aborting the whole SBOM,
// so later phases (vulnerability matching) can reuse this same entry point.
func Generate(ctx context.Context, t *engine.Target) (*SBOM, error) {
	tree, source, err := loadTree(t)
	if err != nil {
		return nil, err
	}
	distro := detectDistro(tree)
	source.Distro = distro.String()

	s := &SBOM{Source: source}
	for _, c := range DefaultCatalogers() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		comps, rels, err := c.Catalog(tree, distro)
		if err != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("%s: %v", c.Name(), err))
			continue
		}
		s.Components = append(s.Components, comps...)
		s.Relationships = append(s.Relationships, rels...)
	}
	s.normalize()
	return s, nil
}

// loadTree resolves the target into a flattened file tree plus source metadata.
func loadTree(t *engine.Target) (*oci.FileTree, Source, error) {
	switch t.Type {
	case engine.TargetFilesystem:
		tree, err := oci.TreeFromDir(t.Location)
		if err != nil {
			return nil, Source{}, fmt.Errorf("sbom: scan filesystem %q: %w", t.Location, err)
		}
		return tree, Source{Type: "filesystem", Name: t.Location}, nil
	case engine.TargetImage:
		img, err := t.Image()
		if err != nil {
			return nil, Source{}, fmt.Errorf("sbom: load image %q: %w", t.Location, err)
		}
		return img.Flatten(), Source{
			Type:        "image",
			Name:        imageName(img, t.Location),
			ImageDigest: img.ConfigDigest,
		}, nil
	default:
		return nil, Source{}, fmt.Errorf("sbom: unsupported target type %q (want image or filesystem)", t.Type)
	}
}

// imageName prefers the image's first repo tag, falling back to the location.
func imageName(img *oci.Image, location string) string {
	if len(img.RepoTags) > 0 && img.RepoTags[0] != "" {
		return img.RepoTags[0]
	}
	return location
}

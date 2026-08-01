package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// --- Image scanning ---------------------------------------------------------
//
// An image is scanned in three passes:
//
//  1. The effective (flattened) filesystem — what actually ships. These are the
//     "live" findings.
//  2. Per-layer content that a later layer deleted or overwrote. The OCI loader
//     keeps every layer's files, and a deleted file's bytes remain in its
//     original blob forever — a secret "removed" in a squash is still one
//     `docker save` away. These findings are flagged Deleted with their layer.
//  3. The image config: the build history (`created_by` = the RUN/ENV lines) and
//     the baked-in environment, where ARG/ENV secrets are recorded verbatim.
//
// Content is deduplicated by (path, content-hash) so a file that is unchanged
// across layers is scanned once, and a secret is reported against the layer
// where its exact bytes live.

// ScanImage scans a loaded image and returns sorted detections. Any non-fatal
// problem encountered along the way (currently: an unparsable image config,
// see scanConfig) is dropped silently here for backward compatibility; use
// ScanImageDetailed to also receive those as warnings.
func (s *Scanner) ScanImage(ctx context.Context, img *oci.Image) []Detection {
	dets, _ := s.scanImage(ctx, img)
	return dets
}

// ScanImageDetailed is ScanImage plus a warnings slice for non-fatal problems
// (e.g. an image config that failed to parse — pass 3 then silently
// contributes nothing, which used to be invisible; see scanConfig). A nil/
// empty warnings slice means nothing degraded.
func (s *Scanner) ScanImageDetailed(ctx context.Context, img *oci.Image) ([]Detection, []string) {
	return s.scanImage(ctx, img)
}

func (s *Scanner) scanImage(ctx context.Context, img *oci.Image) ([]Detection, []string) {
	var out []Detection
	var warnings []string

	// Pass 1: the effective filesystem.
	flat := img.Flatten()
	live := map[string]string{} // path -> content hash of the shipping version
	for _, f := range flat.Files() {
		if err := ctx.Err(); err != nil {
			break
		}
		live[f.Path] = contentHash(f.Data)
		out = append(out, s.scanFile(ctx, f.Path, f.Data, SourceFile, false, -1, "")...)
	}

	// Pass 2: content that a later layer removed or replaced but that remains
	// extractable from its original layer blob.
	scanned := map[string]bool{} // (path|hash) collapse across layers
layers:
	for _, layer := range img.Layers {
		for _, f := range sortedLayerFiles(layer.Files) {
			if err := ctx.Err(); err != nil {
				break layers
			}
			if isWhiteout(f.Path) || f.Data == nil {
				continue
			}
			h := contentHash(f.Data)
			if live[f.Path] == h {
				continue // this exact content is the shipping version (pass 1)
			}
			key := f.Path + "\x00" + h
			if scanned[key] {
				continue
			}
			scanned[key] = true
			out = append(out, s.scanFile(ctx, f.Path, f.Data, SourceDeletedLayer, true, layer.Index, layer.Digest)...)
		}
	}

	// Pass 3: the image config (build history + environment).
	cfgDets, cfgWarnings := s.scanConfig(ctx, img.Config)
	out = append(out, cfgDets...)
	warnings = append(warnings, cfgWarnings...)

	SortDetections(out)
	return out, warnings
}

// imageConfig is the slice of the OCI/docker image config we scan: baked-in
// environment variables and the build-history command lines.
type imageConfig struct {
	Config struct {
		Env []string `json:"Env"`
	} `json:"config"`
	History []struct {
		CreatedBy string `json:"created_by"`
	} `json:"history"`
}

// scanConfig scans the environment and build history recorded in the image
// config. ARG/ENV secrets and secrets on RUN command lines survive here even
// after the layers that used them are gone, so this is a distinct leak
// surface. A config that fails to parse contributes no detections — but
// unlike before, that degradation is now surfaced as a warning rather than
// silently discarded, so a caller (or ScanImageDetailed) can tell "pass 3
// found nothing" apart from "pass 3 never ran".
func (s *Scanner) scanConfig(ctx context.Context, cfg []byte) ([]Detection, []string) {
	if len(cfg) == 0 {
		return nil, nil
	}
	var ic imageConfig
	if err := json.Unmarshal(cfg, &ic); err != nil {
		return nil, []string{fmt.Sprintf("secrets: image config: could not parse config JSON, env/history secrets were not scanned: %v", err)}
	}
	var out []Detection
	for i, env := range ic.Config.Env {
		path := fmt.Sprintf("<image config>/env[%d]", i)
		out = append(out, s.scanFile(ctx, path, []byte(env), SourceImageEnv, false, -1, "")...)
	}
	for i, h := range ic.History {
		if strings.TrimSpace(h.CreatedBy) == "" {
			continue
		}
		path := fmt.Sprintf("<image config>/history[%d]", i)
		out = append(out, s.scanFile(ctx, path, []byte(h.CreatedBy), SourceImageHistory, false, -1, "")...)
	}
	return out, nil
}

// contentHash returns a stable hash of file bytes for dedup and live/deleted
// comparison. It reuses the fingerprint scheme (a truncated SHA-256); collisions
// at this length are not security-relevant here — a false "same content" only
// risks skipping a duplicate scan. Hashes data directly via fingerprintBytes
// rather than round-tripping through a string, since every caller already
// holds these bytes as []byte (avoids a copy on every file, in every layer).
func contentHash(data []byte) string { return fingerprintBytes(data) }

// sortedLayerFiles returns a layer's files ordered by path so scanning is
// deterministic regardless of tar ordering.
func sortedLayerFiles(files []*oci.File) []*oci.File {
	out := make([]*oci.File, len(files))
	copy(out, files)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// isWhiteout reports whether a path is an overlayfs whiteout marker rather than
// real content.
func isWhiteout(p string) bool {
	base := path.Base(p)
	return base == ".wh..wh..opq" || strings.HasPrefix(base, ".wh.")
}

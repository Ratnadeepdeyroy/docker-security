package secrets

import (
	"context"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// --- Filesystem & Dockerfile scanning ---------------------------------------

// ScanTree scans an in-memory file tree (a scanned directory, or any tree built
// via internal/oci) and returns sorted detections. Files are walked in path
// order for determinism.
func (s *Scanner) ScanTree(ctx context.Context, tree *oci.FileTree) []Detection {
	var out []Detection
	for _, f := range tree.Files() {
		if err := ctx.Err(); err != nil {
			break
		}
		out = append(out, s.scanFile(ctx, f.Path, f.Data, SourceFile, false, -1, "")...)
	}
	SortDetections(out)
	return out
}

// ScanDockerfile scans Dockerfile text. Beyond the shared detectors (which
// catch a token pasted into a RUN or ENV value), this is where ARG/ENV/RUN
// secrets that never reach a layer file still live, so it is a first-class
// target rather than an afterthought. The Dockerfile module's DS-RAT-DF-006 flags
// suspicious *key names*; this complements it by fingerprinting the actual
// *values* with the full provider ruleset.
func (s *Scanner) ScanDockerfile(ctx context.Context, path string, content []byte) []Detection {
	return s.ScanText(ctx, path, content, SourceDockerfile)
}

package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// osvFeedBase is the public OSV per-ecosystem export bucket.
const osvFeedBase = "https://osv-vulnerabilities.storage.googleapis.com"

// EcosystemFeedURL returns the public OSV export URL for one ecosystem
// (e.g. "Debian", "Alpine", "PyPI", "npm", "Go"). The ecosystem is
// path-escaped so a stray '#', '?', '%', or '/' in a user-supplied
// --ecosystems value can't be parsed as a URL fragment/query and silently
// truncate the path.
func EcosystemFeedURL(eco string) string {
	return osvFeedBase + "/" + url.PathEscape(eco) + "/all.zip"
}

// unzipOSV expands an OSV all.zip export: every *.json member is one OSV
// record document. Non-JSON members are skipped. The sum of decompressed
// bytes across every member is capped at maxFeedBytes (not just each member
// individually) so a small, highly-compressible archive with many members
// can't be used to inflate gigabytes into memory (a zip bomb). ctx is
// checked once per member so a large hostile archive can be cancelled
// mid-expansion.
func unzipOSV(ctx context.Context, data []byte) ([][]byte, error) {
	return unzipOSVBudget(ctx, data, decompressBudget(len(data)))
}

// decompressBudget sizes the aggregate decompressed cap from the compressed
// size: legitimate OSV exports inflate a small multiple (npm's ~180 MiB zip
// expands to a few hundred MiB), while a zip bomb inflates thousands of times.
// So the budget is 50x the compressed size, floored at maxFeedBytes and ceilinged
// at 2 GiB — big enough for the largest real feed (npm), still a hard wall
// against a hostile archive.
func decompressBudget(compressedLen int) int64 {
	const ceiling = 2 << 30 // 2 GiB
	budget := int64(compressedLen) * 50
	if budget < maxFeedBytes {
		budget = maxFeedBytes
	}
	if budget > ceiling {
		budget = ceiling
	}
	return budget
}

// unzipOSVBudget is unzipOSV with an explicit aggregate decompressed-size
// budget, factored out so tests can exercise the aggregate-cap behavior
// without allocating anywhere near the real 256 MiB maxFeedBytes limit.
func unzipOSVBudget(ctx context.Context, data []byte, budget int64) ([][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("osv zip: %w", err)
	}
	var out [][]byte
	remaining := budget
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		if remaining <= 0 {
			return nil, fmt.Errorf("osv zip: aggregate decompressed size exceeds %d bytes across all members", budget)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("osv zip %s: %w", f.Name, err)
		}
		// Read one byte past the remaining budget so an over-budget member is
		// detected as an error rather than silently truncated to look valid.
		rec, err := io.ReadAll(io.LimitReader(rc, remaining+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("osv zip %s: %w", f.Name, err)
		}
		if int64(len(rec)) > remaining {
			return nil, fmt.Errorf("osv zip: aggregate decompressed size exceeds %d bytes across all members", budget)
		}
		remaining -= int64(len(rec))
		out = append(out, rec)
	}
	return out, nil
}

// MultiFetcher concatenates the records of several fetchers (one per
// ecosystem feed). A failure of any feed fails the whole update — a silently
// partial DB is worse than an error.
type MultiFetcher struct{ Fetchers []Fetcher }

func (m *MultiFetcher) Fetch(ctx context.Context) ([][]byte, error) {
	var all [][]byte
	for _, f := range m.Fetchers {
		recs, err := f.Fetch(ctx)
		if err != nil {
			return nil, err
		}
		all = append(all, recs...)
	}
	return all, nil
}

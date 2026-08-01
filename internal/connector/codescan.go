package connector

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/report"
)

// GitHubCodeScanning uploads the report as SARIF to GitHub's code-scanning API
// (POST /repos/{owner}/{repo}/code-scanning/sarifs). GitHub requires the SARIF
// gzipped then base64-encoded, tied to a commit and ref. This surfaces findings
// in the repo's Security tab and on pull requests.
type GitHubCodeScanning struct {
	APIBase   string // default https://api.github.com (override for GitHub Enterprise)
	Owner     string
	Repo      string
	Token     string
	CommitSHA string
	Ref       string // e.g. "refs/heads/main"
	Client    *http.Client
}

// NewGitHubCodeScanning builds a code-scanning uploader with API defaults.
func NewGitHubCodeScanning(owner, repo, token, commitSHA, ref string) *GitHubCodeScanning {
	return &GitHubCodeScanning{
		APIBase: "https://api.github.com", Owner: owner, Repo: repo,
		Token: token, CommitSHA: commitSHA, Ref: ref,
		Client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (g *GitHubCodeScanning) Name() string { return "github-code-scanning" }

func (g *GitHubCodeScanning) Send(ctx context.Context, r *engine.Report) error {
	encoded, err := gzipBase64SARIF(r)
	if err != nil {
		return err
	}
	payload := map[string]string{
		"commit_sha": g.CommitSHA,
		"ref":        g.Ref,
		"sarif":      encoded,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	base := strings.TrimRight(g.APIBase, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/code-scanning/sarifs", base, g.Owner, g.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "token "+g.Token)
	req.Header.Set("User-Agent", "docker-security")

	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("code-scanning upload returned %s", resp.Status)
	}
	return nil
}

// gzipBase64SARIF renders the report to SARIF, gzips it, and base64-encodes the
// result — exactly the encoding GitHub's sarifs endpoint expects.
func gzipBase64SARIF(r *engine.Report) (string, error) {
	var sarif bytes.Buffer
	if err := (report.SARIF{}).Format(&sarif, r); err != nil {
		return "", fmt.Errorf("render sarif: %w", err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(sarif.Bytes()); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gz.Bytes()), nil
}

func (g *GitHubCodeScanning) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return http.DefaultClient
}

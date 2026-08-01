package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxManifestBytes bounds a single manifest/blob read. Manifests are tiny; a
// registry (or attacker) that streams gigabytes where a manifest is expected is
// a denial-of-service attempt, so we cap the read rather than trust Content-Length.
const maxManifestBytes = 32 << 20 // 32 MiB

// Client talks to an OCI distribution (registry v2) endpoint. The zero value is
// not usable; construct with New. It is safe for concurrent use once built.
type Client struct {
	http      *http.Client
	plainHTTP bool
	userAgent string
	// basicUser/basicPass, if set, are offered on the token endpoint and as a
	// fallback Authorization header. Optional — anonymous pulls work without them.
	basicUser string
	basicPass string
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient injects the underlying HTTP client (inject an httptest client
// in tests, or one with custom TLS/timeouts in production).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithPlainHTTP makes the client speak http:// instead of https://. Use only
// for local/test registries; production registries must be TLS.
func WithPlainHTTP() Option { return func(c *Client) { c.plainHTTP = true } }

// WithBasicAuth sets credentials used to obtain bearer tokens (and as a direct
// fallback). Credentials are never logged.
func WithBasicAuth(user, pass string) Option {
	return func(c *Client) { c.basicUser, c.basicPass = user, pass }
}

// New builds a Client with sensible defaults.
func New(opts ...Option) *Client {
	c := &Client{http: http.DefaultClient, userAgent: "github.com/Ratnadeepdeyroy/docker-security/dsecrat"}
	for _, o := range opts {
		o(c)
	}
	if c.http == nil {
		c.http = http.DefaultClient
	}
	return c
}

func (c *Client) scheme() string {
	if c.plainHTTP {
		return "http"
	}
	return "https"
}

func (c *Client) baseURL(registry string) string {
	return fmt.Sprintf("%s://%s/v2", c.scheme(), registry)
}

// --- Core requests ----------------------------------------------------------

// do performs an authenticated request, transparently handling a single
// WWW-Authenticate Bearer challenge (the registry token dance). It returns the
// response with its body still open; the caller closes it.
func (c *Client) do(ctx context.Context, method, url string, accept string, body io.Reader) (*http.Response, error) {
	req, err := c.newRequest(ctx, method, url, accept, body, "")
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, url, err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	// Attempt the bearer-token flow, then retry once.
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	token, err := c.fetchToken(ctx, challenge)
	if err != nil {
		// No token obtainable (offline, or anonymous not allowed): return a
		// clean error rather than looping.
		return nil, fmt.Errorf("%s %s: authentication required and token fetch failed: %w", method, url, err)
	}
	// Body readers are single-use; for our GET/HEAD paths body is nil, so this is
	// safe. PUT paths pass a fresh reader via the higher-level helpers.
	req2, err := c.newRequest(ctx, method, url, accept, body, token)
	if err != nil {
		return nil, err
	}
	resp2, err := c.http.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("%s %s (authed): %w", method, url, err)
	}
	return resp2, nil
}

func (c *Client) newRequest(ctx context.Context, method, url, accept string, body io.Reader, bearer string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else if c.basicUser != "" {
		req.SetBasicAuth(c.basicUser, c.basicPass)
	}
	return req, nil
}

// Ping checks the registry supports the v2 API (GET /v2/ → 200 or 401). A 401
// still means "v2 registry, but auth required", which is useful posture signal.
func (c *Client) Ping(ctx context.Context, registry string) error {
	resp, err := c.do(ctx, http.MethodGet, c.baseURL(registry)+"/", "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnauthorized:
		return nil
	default:
		return fmt.Errorf("registry ping %s: unexpected status %s", registry, resp.Status)
	}
}

// --- Manifests --------------------------------------------------------------

// GetManifest fetches the manifest for a reference (by digest if pinned, else by
// tag), verifies the bytes against the digest when the reference pinned one, and
// returns the raw bytes + media type + digest. Verifying the digest here is the
// linchpin of the whole trust chain: everything downstream signs or reasons over
// this digest, so a registry that lies about content is caught immediately.
func (c *Client) GetManifest(ctx context.Context, ref Reference) (*RawManifest, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", c.baseURL(ref.Registry), ref.Repository, ref.RefForPull())
	resp, err := c.do(ctx, http.MethodGet, url, manifestMediaTypes(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError("get manifest "+ref.String(), resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", ref.String(), err)
	}
	digest := Digest(data)
	if ref.Digest != "" {
		if err := VerifyDigest(data, ref.Digest); err != nil {
			return nil, fmt.Errorf("get manifest %s: %w", ref.String(), err)
		}
	}
	mt := resp.Header.Get("Content-Type")
	if mt == "" {
		mt = MediaTypeOCIManifest
	}
	return &RawManifest{Bytes: data, MediaType: mt, Digest: digest}, nil
}

// ResolveDigest returns the manifest digest for a reference. If the reference is
// already digest-pinned it is returned as-is; otherwise a HEAD resolves the tag.
func (c *Client) ResolveDigest(ctx context.Context, ref Reference) (string, error) {
	if ref.Digest != "" {
		return ref.Digest, nil
	}
	url := fmt.Sprintf("%s/%s/manifests/%s", c.baseURL(ref.Registry), ref.Repository, ref.Tag)
	resp, err := c.do(ctx, http.MethodHead, url, manifestMediaTypes(), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", statusError("head manifest "+ref.String(), resp)
	}
	if d := resp.Header.Get("Docker-Content-Digest"); d != "" {
		return d, nil
	}
	// Some registries omit the header on HEAD; fall back to a GET.
	rm, err := c.GetManifest(ctx, ref)
	if err != nil {
		return "", err
	}
	return rm.Digest, nil
}

// PutManifest uploads a manifest under a reference (tag or digest) and returns
// its descriptor. Used to push signatures/attestations as referrer manifests.
func (c *Client) PutManifest(ctx context.Context, registry, repo, reference, mediaType string, data []byte) (Descriptor, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", c.baseURL(registry), repo, reference)
	req, err := c.newRequest(ctx, http.MethodPut, url, "", strings.NewReader(string(data)), "")
	if err != nil {
		return Descriptor{}, err
	}
	req.Header.Set("Content-Type", mediaType)
	resp, err := c.http.Do(req)
	if err != nil {
		return Descriptor{}, fmt.Errorf("put manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return Descriptor{}, statusError("put manifest", resp)
	}
	return Descriptor{MediaType: mediaType, Digest: Digest(data), Size: int64(len(data))}, nil
}

// --- Blobs ------------------------------------------------------------------

// GetBlob fetches a blob by digest and verifies its content.
func (c *Client) GetBlob(ctx context.Context, registry, repo, digest string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s/blobs/%s", c.baseURL(registry), repo, digest)
	resp, err := c.do(ctx, http.MethodGet, url, "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError("get blob", resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	if err != nil {
		return nil, fmt.Errorf("read blob: %w", err)
	}
	if err := VerifyDigest(data, digest); err != nil {
		return nil, fmt.Errorf("get blob: %w", err)
	}
	return data, nil
}

// PutBlob uploads a blob via the monolithic (POST-then-PUT) flow and returns its
// descriptor.
func (c *Client) PutBlob(ctx context.Context, registry, repo string, data []byte) (Descriptor, error) {
	// Start an upload session.
	start := fmt.Sprintf("%s/%s/blobs/uploads/", c.baseURL(registry), repo)
	resp, err := c.do(ctx, http.MethodPost, start, "", nil)
	if err != nil {
		return Descriptor{}, err
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || loc == "" {
		return Descriptor{}, fmt.Errorf("start blob upload: unexpected status %s", resp.Status)
	}
	digest := Digest(data)
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	putURL := c.absolute(registry, loc) + sep + "digest=" + digest
	req, err := c.newRequest(ctx, http.MethodPut, putURL, "", strings.NewReader(string(data)), "")
	if err != nil {
		return Descriptor{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	put, err := c.http.Do(req)
	if err != nil {
		return Descriptor{}, fmt.Errorf("put blob: %w", err)
	}
	defer put.Body.Close()
	if put.StatusCode != http.StatusCreated {
		return Descriptor{}, statusError("put blob", put)
	}
	return Descriptor{MediaType: "application/octet-stream", Digest: digest, Size: int64(len(data))}, nil
}

// absolute resolves a (possibly relative) upload Location against the registry.
func (c *Client) absolute(registry, loc string) string {
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	if strings.HasPrefix(loc, "/") {
		return fmt.Sprintf("%s://%s%s", c.scheme(), registry, loc)
	}
	return c.baseURL(registry) + "/" + loc
}

// --- Tags -------------------------------------------------------------------

// ListTags returns the tags in a repository.
func (c *Client) ListTags(ctx context.Context, registry, repo string) ([]string, error) {
	url := fmt.Sprintf("%s/%s/tags/list", c.baseURL(registry), repo)
	resp, err := c.do(ctx, http.MethodGet, url, "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError("list tags", resp)
	}
	var out struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode tags: %w", err)
	}
	return out.Tags, nil
}

// statusError builds an error from a non-2xx response, including a short snippet
// of the body to aid debugging without dumping unbounded output.
func statusError(op string, resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(snippet))
	if msg == "" {
		return fmt.Errorf("%s: %s", op, resp.Status)
	}
	return fmt.Errorf("%s: %s: %s", op, resp.Status, msg)
}

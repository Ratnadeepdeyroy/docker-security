package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// --- Bearer token flow ------------------------------------------------------
//
// Registries authenticate with the "docker token" scheme: an unauthenticated
// request gets a 401 carrying a WWW-Authenticate: Bearer realm=...,service=...,
// scope=... challenge. The client fetches a token from the realm and retries.
// We implement just enough of RFC 6750 / the Docker token spec to pull public
// content anonymously and to use basic-auth credentials when provided. Tokens
// are request-scoped and never persisted or logged.

// fetchToken satisfies a Bearer challenge and returns an access token. An empty
// challenge (or one we cannot parse) is an error, so callers fail cleanly rather
// than silently retrying unauthenticated.
func (c *Client) fetchToken(ctx context.Context, challenge string) (string, error) {
	params, err := parseBearerChallenge(challenge)
	if err != nil {
		return "", err
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("bearer challenge missing realm")
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("parse token realm %q: %w", realm, err)
	}
	q := u.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	if scope := params["scope"]; scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	if c.basicUser != "" {
		req.SetBasicAuth(c.basicUser, c.basicPass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tok.Token != "" {
		return tok.Token, nil
	}
	if tok.AccessToken != "" {
		return tok.AccessToken, nil
	}
	return "", fmt.Errorf("token response contained no token")
}

// parseBearerChallenge parses a `Bearer key="value",key2="value2"` header into a
// map. It tolerates unquoted values and surrounding whitespace.
func parseBearerChallenge(header string) (map[string]string, error) {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return nil, fmt.Errorf("not a Bearer challenge: %q", header)
	}
	rest := strings.TrimSpace(header[len("bearer "):])
	out := map[string]string{}
	for _, part := range splitTopLevelCommas(rest) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		out[key] = val
	}
	return out, nil
}

// splitTopLevelCommas splits on commas that are not inside double quotes, so a
// scope value containing commas is not torn apart.
func splitTopLevelCommas(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch r {
		case '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case ',':
			if inQuote {
				cur.WriteRune(r)
			} else {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}

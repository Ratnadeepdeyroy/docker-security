// Package dockercli is a thin, guarded wrapper around the local `docker` CLI.
// It powers a convenience feature of the dashboard/server: auto-detecting the
// images and containers already on the host and scanning them on click, or
// scanning an image by reference (the server `docker save`s it to a temp tar).
//
// It is deliberately NOT part of the deterministic analysis core — it is an
// opt-in host integration that only works when a docker binary is present. All
// exec calls pass arguments as a vector (never a shell string) and validate any
// user-supplied reference against a strict charset, so there is no shell- or
// argument-injection surface.
package dockercli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Image is a locally-present image.
type Image struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	ID         string `json:"id"`
	Size       string `json:"size"`
	Created    string `json:"created"`
	// Ref is the best reference to scan by (repo:tag, or the ID when untagged).
	Ref string `json:"ref"`
}

// Container is a local container (running or stopped).
type Container struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"`
	State  string `json:"state"`
	ID     string `json:"id"`
}

// Available reports whether a docker binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// refRe is the safe charset for an image reference/ID we will pass to docker.
// It must not begin with '-' (would be read as a flag).
var refRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)

// ValidRef reports whether ref is a safe image reference or ID.
func ValidRef(ref string) bool { return refRe.MatchString(ref) }

// Images lists local images (excluding dangling <none> repos, which cannot be
// referenced by name).
func Images(ctx context.Context) ([]Image, error) {
	out, err := run(ctx, "images", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	var images []Image
	for _, line := range nonEmptyLines(out) {
		var raw struct {
			Repository, Tag, ID, Size, CreatedSince string
		}
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		img := Image{
			Repository: raw.Repository, Tag: raw.Tag, ID: shortID(raw.ID),
			Size: raw.Size, Created: raw.CreatedSince,
		}
		switch {
		case raw.Repository != "" && raw.Repository != "<none>" && raw.Tag != "<none>":
			img.Ref = raw.Repository + ":" + raw.Tag
		default:
			img.Ref = shortID(raw.ID) // dangling: reference by id
		}
		images = append(images, img)
	}
	return images, nil
}

// Containers lists all containers (running and stopped).
func Containers(ctx context.Context) ([]Container, error) {
	out, err := run(ctx, "ps", "-a", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	var cs []Container
	for _, line := range nonEmptyLines(out) {
		var raw struct {
			Names, Image, Status, State, ID string
		}
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		cs = append(cs, Container{Name: raw.Names, Image: raw.Image, Status: raw.Status, State: raw.State, ID: shortID(raw.ID)})
	}
	return cs, nil
}

// NormalizeRef turns user input into a pullable image reference. It accepts a
// plain ref (`ubuntu:latest`, `ghcr.io/org/app@sha256:…`), a Docker Hub web URL
// (`https://hub.docker.com/_/ubuntu`, `.../r/bitnami/nginx`), or any registry
// URL with a scheme (`https://ghcr.io/org/app:tag`). It returns (ref, true) on
// success, or ("", false) when the input cannot be a reference (e.g. a webpage
// path, or something with spaces).
func NormalizeRef(input string) (string, bool) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", false
	}
	// Docker Hub web URL → the underlying image reference.
	if i := strings.Index(s, "hub.docker.com/"); i >= 0 {
		rest := trimURLNoise(s[i+len("hub.docker.com/"):])
		segs := strings.Split(rest, "/")
		var ref string
		switch {
		case segs[0] == "_" && len(segs) >= 2: // official image: /_/ubuntu
			ref = segs[1]
		case segs[0] == "r" && len(segs) >= 3: // user/org: /r/bitnami/nginx
			ref = segs[1] + "/" + segs[2]
		case segs[0] == "layers" && len(segs) >= 3: // deep link: /layers/library/ubuntu/...
			ref = segs[2]
		default:
			ref = strings.Join(segs, "/")
		}
		if ValidRef(ref) {
			return ref, true
		}
		return "", false
	}
	// Any other URL with a scheme → strip the scheme and keep host/path as a ref.
	if j := strings.Index(s, "://"); j >= 0 {
		s = trimURLNoise(s[j+3:])
	}
	if ValidRef(s) {
		return s, true
	}
	return "", false
}

// trimURLNoise drops a query string, fragment, and any trailing slash.
func trimURLNoise(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, "/")
}

// EnsureLocal makes ref available to `docker save`: if the image is not already
// present, it is pulled. Requires network only on a cache miss.
func EnsureLocal(ctx context.Context, ref string) error {
	if !ValidRef(ref) {
		return fmt.Errorf("refusing unsafe image reference %q", ref)
	}
	if _, err := run(ctx, "image", "inspect", ref); err == nil {
		return nil // already local
	}
	if _, err := run(ctx, "pull", ref); err != nil {
		return fmt.Errorf("pull %q: %w", ref, err)
	}
	return nil
}

// Save writes image ref to dest as a docker-save tarball. ref is validated.
func Save(ctx context.Context, ref, dest string) error {
	if !ValidRef(ref) {
		return fmt.Errorf("refusing unsafe image reference %q", ref)
	}
	if _, err := run(ctx, "save", ref, "-o", dest); err != nil {
		return fmt.Errorf("docker save %q: %w", ref, err)
	}
	return nil
}

func run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("docker %s: %s", args[0], msg)
	}
	return stdout.Bytes(), nil
}

func nonEmptyLines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

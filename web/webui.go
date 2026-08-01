// Package web serves the Phase 9 dashboard: a self-contained, offline single-page
// app over the same HTTP API the CLI and connectors use. It embeds its assets so
// the binary ships the UI with no external files, CDNs, or network calls.
//
// It intentionally exposes the same surface as internal/web — package name web,
// a single Handler() constructor — so the master swaps it in by changing one
// import path in server.go (docker-security/internal/web →
// docker-security/web); the web.Handler() call site is unchanged. The richer app
// consumes the store's read endpoints (/v1/inventory, /v1/findings, /v1/trends,
// /v1/scans) and degrades gracefully when the store is not enabled.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var assets embed.FS

// Handler serves the embedded dashboard (index.html) and its static assets.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

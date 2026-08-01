// Package web serves the embedded single-page dashboard. It is a frontend over
// the same HTTP API the CLI and connectors use — the UI just calls /v1/scan.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets
var assets embed.FS

// Handler serves the embedded dashboard (index.html) and its static assets.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

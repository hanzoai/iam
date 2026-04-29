// Package ui embeds the IAM admin dashboard built with Vite + React.
//
// The Go HTTP handler serves the admin UI at the /_/iam/ path.
// Run `pnpm --dir ui build` in this directory to produce dist/; the
// //go:embed directive below picks up the resulting static assets.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// DistDirFS returns a rooted fs.FS pointing at dist/ so it can be passed
// directly to http.FileServer or Beego's static handler.
func DistDirFS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("iam-ui: dist/ missing — run `pnpm --dir ui build` first: " + err.Error())
	}
	return sub
}

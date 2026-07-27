// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Command openapi renders IAM's live route surface into the canonical spec.
//
//	go run ./cmd/openapi -spec ../openapi/iam/openapi.yaml          # write
//	go run ./cmd/openapi -spec ../openapi/iam/openapi.yaml -verify  # check only
//
// The spec is DERIVED from routes.Route — the same function the server binds at
// boot — so the published contract cannot describe a surface IAM does not serve.
//
// That is not a hypothetical failure. The hand-authored spec this replaces
// declared 150 paths, and the running server served NONE of them: it documented
// /v1/iam/applications/{id} and /v1/iam/auth/login against a server that served
// /v1/iam/application and /v1/iam/login. A single {id} segment could not have
// worked in any case — an entity's identity here is the pair (owner, name), and
// Go decodes %2F back to "/" in URL.Path before routing, so a percent-encoded
// composite key matches no route at all. Everything generated from that spec —
// the CLI's IAM commands, the SDK clients — was calling routes that answer 404.
//
// Only the region between the generated markers is written. Anything outside them
// is hand-authored and preserved.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"
	yaml "go.yaml.in/yaml/v3"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/schema"
)

const (
	beginMarker = "  # BEGIN generated: IAM route surface (go run ./cmd/openapi) — DO NOT EDIT BY HAND"
	endMarker   = "  # END generated: IAM route surface"
)

func main() {
	spec := flag.String("spec", "", "path to the canonical iam/openapi.yaml")
	verify := flag.Bool("verify", false, "exit non-zero if the spec is out of date; write nothing")
	flag.Parse()

	if *spec == "" {
		fail("-spec is required (path to hanzoai/openapi iam/openapi.yaml)")
	}

	rendered, err := render()
	if err != nil {
		fail("render: %v", err)
	}

	current, err := os.ReadFile(*spec)
	if err != nil {
		fail("read %s: %v", *spec, err)
	}
	next, err := splice(string(current), rendered)
	if err != nil {
		fail("%v", err)
	}

	if *verify {
		if string(current) != next {
			fail("%s is out of date — run: go run ./cmd/openapi -spec %s", *spec, *spec)
		}
		fmt.Println("openapi: spec matches the route surface")
		return
	}
	if err := os.WriteFile(*spec, []byte(next), 0o644); err != nil {
		fail("write %s: %v", *spec, err)
	}
	fmt.Printf("openapi: wrote the IAM route surface to %s\n", *spec)
}

// render builds the paths block from the REAL registered router.
//
// It boots the routes against a throwaway store because registration is what
// declares the surface — there is no separate table to read, and inventing one
// would be the second source of truth this command exists to remove.
func render() (string, error) {
	_ = schema.Kinds()
	dir, err := os.MkdirTemp("", "iam-openapi")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "iam.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		return "", err
	}
	defer db.Close()

	app := zip.New(zip.Config{
		AppName:               "iam",
		DisableStartupMessage: true,
		OpenAPI: zip.OpenAPIConfig{
			Title:       "Hanzo IAM",
			Description: "Identity and access management. Every route is /v1/iam/<resource>; an entity is addressed by the pair (owner, name).",
			Version:     "v1",
		},
	})
	routes.Route(app, db)

	paths, _ := app.OpenAPISpec()["paths"].(map[string]map[string]any)
	if len(paths) == 0 {
		return "", fmt.Errorf("no typed ops registered — refusing to publish an empty surface")
	}

	// Emit sorted so the file is stable: a diff must mean the surface changed.
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Marshalled one path at a time: a Go map has no order, and yaml.v3 preserves
	// none, so emitting the whole map would reshuffle the file on every run and
	// every diff would be noise.
	var b strings.Builder
	for _, k := range keys {
		out, err := yaml.Marshal(map[string]any{k: paths[k]})
		if err != nil {
			return "", err
		}
		b.WriteString(string(out))
	}
	return indent(b.String()), nil
}

// indent shifts the rendered block under the top-level `paths:` key.
func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("  " + line + "\n")
	}
	return b.String()
}

// splice replaces the generated region, creating it at the end of `paths:` the
// first time. Content outside the markers is never touched.
func splice(current, block string) (string, error) {
	begin := strings.Index(current, beginMarker)
	end := strings.Index(current, endMarker)
	switch {
	case begin >= 0 && end > begin:
		return current[:begin] + beginMarker + "\n" + block + endMarker + current[end+len(endMarker):], nil
	case begin >= 0 || end >= 0:
		return "", fmt.Errorf("spec has only one of the two generated markers; fix it by hand")
	}

	// First run: append the region at the end of the top-level paths: block.
	idx := strings.Index(current, "\npaths:\n")
	if idx < 0 {
		return "", fmt.Errorf("spec has no top-level `paths:` key to extend")
	}
	rest := current[idx+len("\npaths:\n"):]
	// The paths block ends at the next top-level (column-0) key.
	offset := len(current)
	for _, line := range strings.SplitAfter(rest, "\n") {
		trimmed := strings.TrimRight(line, "\n")
		if trimmed != "" && !strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, "#") {
			offset = idx + len("\npaths:\n") + strings.Index(rest, line)
			break
		}
	}
	return current[:offset] + beginMarker + "\n" + block + endMarker + "\n" + current[offset:], nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "openapi: "+format+"\n", args...)
	os.Exit(1)
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package principal_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// path is this package, as an import names it.
const path = "github.com/hanzoai/iam/internal/principal"

// caller is where authentication lives: the one place in the tree that resolves a
// bearer, and therefore the one place that may say who a request acts as.
const caller = "internal/authz/authz.go"

// Bind is the only way a principal enters a request context, and Scope reads
// whatever it finds there — so a second caller of Bind is a second answer to
// "who is this?", one of them taken without verifying anything. The ctx key is
// unexported, which leaves Bind as the whole surface; this walks the tree and
// holds it to its one caller.
//
// It reads the SOURCE rather than the package graph on purpose. A widening is
// somebody writing principal.Bind somewhere new, and that is exactly what a
// syntax walk sees.
func TestBindHasOneCaller(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var found []string

	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		// What this file calls the package, if it imports it at all.
		name := ""
		for _, im := range f.Imports {
			v, err := strconv.Unquote(im.Path.Value)
			if err != nil || v != path {
				continue
			}
			name = "principal"
			if im.Name != nil {
				name = im.Name.Name
			}
		}
		if name == "" {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Bind" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == name {
				rel, _ := filepath.Rel(root, p)
				found = append(found, rel)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(found) != 1 || found[0] != caller {
		t.Fatalf("Bind is called from %v, want exactly [%s].\n"+
			"A principal enters a request context where a bearer was verified and nowhere "+
			"else — every Scope answer downstream is only as good as that.", found, caller)
	}
}

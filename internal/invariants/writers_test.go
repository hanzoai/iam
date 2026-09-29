// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invariants_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	policy "github.com/hanzoai/authz"
	"golang.org/x/tools/go/packages"
)

const schemaPath = "github.com/hanzoai/iam/pkg/schema"

// site is a declaration of the module that writes an account's owner.
type site struct {
	file, decl string
}

func (s site) String() string { return s.file + ":" + s.decl }

// writes is what the type-checked module does to an account's owner: the sites
// that set it to the admin directory (a constant), the sites that set it to a
// value only known when they run, and the callers of newAdmin.
type writes struct {
	admin, dynamic []site
	callers        []site
}

var (
	loadOnce sync.Once
	loaded   writes
	loadErr  error
)

// scan type-checks every non-test package of the module and reads each write of
// an account's owner through the types, so an owner reached through a local
// constant, a renamed import, a package-level closure or a variable is seen for
// what it is. An owner is written by: a schema.User literal naming Owner; an
// assignment to the Owner field of a schema.User; an assignment of a whole
// schema.User (which carries whatever Owner it holds); or SetId on a schema.User.
func scan(t *testing.T) writes {
	t.Helper()
	loadOnce.Do(func() {
		cfg := &packages.Config{
			Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
			Dir:  root(t),
		}
		pkgs, err := packages.Load(cfg, "./...")
		if err != nil {
			loadErr = err
			return
		}
		mod := root(t)
		for _, p := range pkgs {
			if len(p.Errors) > 0 {
				loadErr = fmt.Errorf("%s: %v", p.PkgPath, p.Errors[0])
				return
			}
			for _, f := range p.Syntax {
				rel, _ := filepath.Rel(mod, p.Fset.Position(f.Pos()).Filename)
				for _, d := range f.Decls {
					inspect(p.TypesInfo, filepath.ToSlash(rel), d, &loaded)
				}
			}
		}
	})
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	return loaded
}

func declName(d ast.Decl) string {
	switch x := d.(type) {
	case *ast.FuncDecl:
		if x.Recv != nil && len(x.Recv.List) > 0 {
			return "(" + types.ExprString(x.Recv.List[0].Type) + ")." + x.Name.Name
		}
		return x.Name.Name
	case *ast.GenDecl:
		for _, s := range x.Specs {
			if v, ok := s.(*ast.ValueSpec); ok && len(v.Names) > 0 {
				return "var " + v.Names[0].Name
			}
		}
	}
	return "decl"
}

// isUser reports whether t is schema.User, or a pointer to it.
func isUser(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == schemaPath && n.Obj().Name() == "User"
}

// owner classifies a value written as an owner: the admin directory, another
// constant, or a value known only when the code runs.
func owner(info *types.Info, e ast.Expr) string {
	if tv, ok := info.Types[e]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		if constant.StringVal(tv.Value) == policy.AdminOrg {
			return "admin"
		}
		return "constant"
	}
	return "dynamic"
}

// key classifies a storage key written with SetId.
func key(info *types.Info, e ast.Expr) string {
	if tv, ok := info.Types[e]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		if strings.HasPrefix(constant.StringVal(tv.Value), policy.AdminOrg+"/") {
			return "admin"
		}
		return "constant"
	}
	if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.ADD {
		if owner(info, b.X) == "admin" || key(info, b.X) == "admin" {
			return "admin"
		}
	}
	return "dynamic"
}

func inspect(info *types.Info, file string, d ast.Decl, w *writes) {
	s := site{file: file, decl: declName(d)}
	add := func(kind string) {
		switch kind {
		case "admin":
			w.admin = append(w.admin, s)
		case "dynamic":
			w.dynamic = append(w.dynamic, s)
		}
	}
	ast.Inspect(d, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if tv, ok := info.Types[x]; ok && isUser(tv.Type) {
				for _, e := range x.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Owner" {
							add(owner(info, kv.Value))
						}
					}
				}
			}
		case *ast.AssignStmt:
			for i, l := range x.Lhs {
				var rhs ast.Expr
				if len(x.Rhs) == len(x.Lhs) {
					rhs = x.Rhs[i]
				}
				if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Owner" {
					if tv, ok := info.Types[sel.X]; ok && isUser(tv.Type) {
						if rhs == nil {
							add("dynamic")
						} else {
							add(owner(info, rhs))
						}
						continue
					}
				}
				// A whole account assigned carries the owner it holds.
				if tv, ok := info.Types[l]; ok && isUser(tv.Type) && !isPointer(tv.Type) {
					if _, lit := rhs.(*ast.CompositeLit); !lit {
						add("dynamic")
					}
				}
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok {
				if obj, ok := info.Uses[id].(*types.Func); ok && obj.Name() == "newAdmin" && obj.Pkg() != nil &&
					obj.Pkg().Path() == "github.com/hanzoai/iam/internal/superadmin" {
					w.callers = append(w.callers, s)
				}
			}
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || len(x.Args) != 1 {
				return true
			}
			if sel.Sel.Name == "SetId" {
				if tv, ok := info.Types[sel.X]; ok && isUser(tv.Type) {
					add(key(info, x.Args[0]))
				}
			}
		}
		return true
	})
}

func isPointer(t types.Type) bool {
	_, ok := t.(*types.Pointer)
	return ok
}

func strs(ss []site) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

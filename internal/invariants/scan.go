// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invariants

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// ---- R7 row 1: records under admin ----

// kinds maps every kind schema.Kinds registers to a reader of its rows filed
// under admin, answering how many of them are not SuperAdmin accounts.
var kinds = map[string]func(context.Context, orm.DB) (int, error){
	"users": func(ctx context.Context, db orm.DB) (int, error) {
		us, err := underAdmin[schema.User](ctx, db)
		n := 0
		for _, u := range us {
			if !u.SuperAdmin() {
				n++
			}
		}
		return n, err
	},
	"organizations":        count[schema.Organization],
	"applications":         count[schema.Application],
	"providers":            count[schema.Provider],
	"roles":                count[schema.Role],
	"permissions":          count[schema.Permission],
	"certs":                count[schema.Cert],
	"keys":                 count[schema.Key],
	"webauthn_credentials": count[schema.WebauthnCredential],
	"sessions":             count[schema.Session],
	"tokens":               count[schema.Token],
	"audit_logs":           count[schema.AuditLog],
	"invitations":          count[schema.Invitation],
	"verifications":        count[schema.VerificationRecord],
	"projects":             count[schema.Project],
	"workspaces":           count[schema.Workspace],
	"federation_states":    count[schema.FederationState],
	"challenges":           count[schema.Challenge],
	"wallets":              count[schema.Wallet],
	"login_challenges":     count[schema.LoginChallenge],
	"memberships":          count[schema.Membership],
	"teams":                count[schema.Team],
}

func underAdmin[T any](ctx context.Context, db orm.DB) ([]*T, error) {
	rows, err := orm.TypedQuery[T](db).Filter("Owner=", policy.AdminOrg).GetAll(ctx)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, nil
	}
	return rows, err
}

func count[T any](ctx context.Context, db orm.DB) (int, error) {
	rows, err := underAdmin[T](ctx, db)
	return len(rows), err
}

// AdminRecords scans every kind for records filed under admin that are not
// SuperAdmin accounts and answers the kinds that hold any, sorted.
func AdminRecords(ctx context.Context, db orm.DB) ([]string, error) {
	if registered := schema.Kinds(); len(registered) != len(kinds) {
		return nil, fmt.Errorf("invariants: schema registers %d kinds and the scan reads %d", len(registered), len(kinds))
	}
	var out []string
	for _, k := range schema.Kinds() {
		read, ok := kinds[k]
		if !ok {
			return nil, fmt.Errorf("invariants: kind %q is registered and not scanned", k)
		}
		n, err := read(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("invariants: scan %s: %w", k, err)
		}
		if n > 0 {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

// ---- R7 row 3: account-level admin fields ----

// forbidden are the words that name authority when they appear on an account.
var forbidden = []string{"admin", "role", "roles", "group", "groups", "superadmin", "globaladmin", "isadmin", "sudo"}

// AdminFields walks every type reachable from schema.User and answers each field
// whose name, json key or orm column names authority, as Type.Field.
func AdminFields() []string {
	var out []string
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Anonymous && strings.HasPrefix(f.Type.String(), "orm.Model") {
				continue
			}
			names := []string{f.Name, tagName(f.Tag.Get("json")), tagName(f.Tag.Get("orm"))}
			for _, n := range names {
				if n != "" && authority(n) {
					out = append(out, t.Name()+"."+f.Name)
					break
				}
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(schema.User{}))
	slices.Sort(out)
	return slices.Compact(out)
}

func tagName(tag string) string {
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" || strings.Contains(name, ":") {
		return ""
	}
	return name
}

// authority reports whether an identifier names authority: the whole identifier,
// lowercased, or any of its camelCase or snake_case words.
func authority(ident string) bool {
	if slices.Contains(forbidden, strings.ToLower(ident)) {
		return true
	}
	for _, w := range words(ident) {
		if slices.Contains(forbidden, w) {
			return true
		}
	}
	return false
}

func words(ident string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(ident)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-':
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) || (i+1 < len(rs) && unicode.IsLower(rs[i+1]))):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

// ---- R7 row 7: who files an account under admin ----

// Site is a statement that files an account under admin.
type Site struct {
	File string // relative to the module root
	Func string
	Line int
}

func (s Site) String() string { return fmt.Sprintf("%s:%s", s.File, s.Func) }

// AdminWriters parses every non-test Go file under root and answers each
// statement that sets an account's owner to the admin namespace or keys an
// account admin/…: a schema.User literal whose Owner is admin, an assignment of
// admin to the Owner of a variable holding a schema.User, or SetId("admin/"…) on
// one.
func AdminWriters(root string) ([]Site, error) {
	var out []Site
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n != "." && (strings.HasPrefix(n, ".") || n == "testdata" || n == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		inSchema := f.Name.Name == "schema"
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, line := range writers(fset, fn, inSchema) {
				out = append(out, Site{File: filepath.ToSlash(rel), Func: fn.Name.Name, Line: line})
			}
		}
		return nil
	})
	return out, err
}

// Calls answers every call of the function fn of package pkg across every
// non-test file under root, as file:func: an unqualified call inside pkg, or
// pkg.fn from outside it.
func Calls(root, pkg, fn string) ([]string, error) {
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		local := f.Name.Name == pkg
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if !ok || d.Body == nil {
				continue
			}
			ast.Inspect(d.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch x := c.Fun.(type) {
				case *ast.Ident:
					if local && x.Name == fn {
						out = append(out, filepath.ToSlash(rel)+":"+d.Name.Name)
					}
				case *ast.SelectorExpr:
					if p, ok := x.X.(*ast.Ident); ok && p.Name == pkg && x.Sel.Name == fn {
						out = append(out, filepath.ToSlash(rel)+":"+d.Name.Name)
					}
				}
				return true
			})
		}
		return nil
	})
	return out, err
}

// writers answers the lines in fn that file an account under admin.
func writers(fset *token.FileSet, fn *ast.FuncDecl, inSchema bool) []int {
	users := map[string]bool{}
	isUserType := func(e ast.Expr) bool { return userType(e, inSchema) }
	if fn.Type.Params != nil {
		for _, p := range fn.Type.Params.List {
			if isUserType(p.Type) {
				for _, n := range p.Names {
					users[n.Name] = true
				}
			}
		}
	}
	if fn.Type.Results != nil {
		for _, p := range fn.Type.Results.List {
			if isUserType(p.Type) {
				for _, n := range p.Names {
					users[n.Name] = true
				}
			}
		}
	}
	// Variables that hold a user: declared with a user type, or assigned a
	// user literal or orm.New[schema.User].
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ValueSpec:
			if s.Type != nil && isUserType(s.Type) {
				for _, id := range s.Names {
					users[id.Name] = true
				}
			}
			for i, v := range s.Values {
				if i < len(s.Names) && makesUser(v, inSchema) {
					users[s.Names[i].Name] = true
				}
			}
		case *ast.AssignStmt:
			for i, r := range s.Rhs {
				if i < len(s.Lhs) && makesUser(r, inSchema) {
					if id, ok := s.Lhs[i].(*ast.Ident); ok {
						users[id.Name] = true
					}
				}
			}
		}
		return true
	})
	var lines []int
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.CompositeLit:
			if isUserType(s.Type) {
				for _, e := range s.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Owner" && adminExpr(kv.Value) {
							lines = append(lines, fset.Position(kv.Pos()).Line)
						}
					}
				}
			}
		case *ast.AssignStmt:
			if len(s.Lhs) != len(s.Rhs) {
				return true
			}
			for i, l := range s.Lhs {
				sel, ok := l.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Owner" || !adminExpr(s.Rhs[i]) {
					continue
				}
				if id, ok := sel.X.(*ast.Ident); ok && users[id.Name] {
					lines = append(lines, fset.Position(s.Pos()).Line)
				}
			}
		case *ast.CallExpr:
			sel, ok := s.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SetId" || len(s.Args) != 1 {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && users[id.Name] && adminKey(s.Args[0]) {
				lines = append(lines, fset.Position(s.Pos()).Line)
			}
		}
		return true
	})
	return lines
}

// userType reports whether e spells schema.User, *schema.User, or — inside
// package schema — User.
func userType(e ast.Expr, inSchema bool) bool {
	switch t := e.(type) {
	case *ast.StarExpr:
		return userType(t.X, inSchema)
	case *ast.SelectorExpr:
		p, ok := t.X.(*ast.Ident)
		return ok && p.Name == "schema" && t.Sel.Name == "User"
	case *ast.Ident:
		return inSchema && t.Name == "User"
	}
	return false
}

// makesUser reports whether e produces a user: a literal, its address, or
// orm.New[schema.User](…).
func makesUser(e ast.Expr, inSchema bool) bool {
	switch x := e.(type) {
	case *ast.UnaryExpr:
		return makesUser(x.X, inSchema)
	case *ast.CompositeLit:
		return userType(x.Type, inSchema)
	case *ast.CallExpr:
		if ix, ok := x.Fun.(*ast.IndexExpr); ok {
			if sel, ok := ix.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "New" {
				return userType(ix.Index, inSchema)
			}
		}
	}
	return false
}

// adminExpr reports whether e names the admin namespace: the literal, or a
// constant spelled AdminOrg or DirAdmin.
func adminExpr(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		v, err := strconv.Unquote(x.Value)
		return err == nil && v == policy.AdminOrg
	case *ast.SelectorExpr:
		return x.Sel.Name == "AdminOrg" || x.Sel.Name == "DirAdmin"
	case *ast.Ident:
		return x.Name == "AdminOrg" || x.Name == "DirAdmin"
	case *ast.ParenExpr:
		return adminExpr(x.X)
	}
	return false
}

// adminKey reports whether e builds a key under admin: "admin/…" or admin + "/…".
func adminKey(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		v, err := strconv.Unquote(x.Value)
		return err == nil && strings.HasPrefix(v, policy.AdminOrg+"/")
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return false
		}
		if adminExpr(x.X) {
			return true
		}
		return adminKey(x.X)
	case *ast.ParenExpr:
		return adminKey(x.X)
	}
	return false
}

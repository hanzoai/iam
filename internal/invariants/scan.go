// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invariants

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
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

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package routes_test

// A URL CARRIES WHAT IT ADDRESSES, AND NOTHING ELSE.
//
// zip binds a typed op's scalars from the URL on EVERY method, and binds them
// AFTER the body — so a field with no `url:"-"` is not merely also-settable from
// the URL, it OVERRIDES what the body sent. A URL is the part of a request that
// gets written down: access and proxy logs, browser history, the Referer of
// whatever the answer links to. It is also what a generated SDK offers as a
// flag, so a field reachable there is a field clients will put there.
//
// This check used to run the other way round: derive the secret set from
// schema.Mask and prove no member of it binds. That is blind exactly where it
// matters — a type with NO Mask declares no secrets, so Cert.Certificate,
// Token.AccessTokenHash, Permission.Effect, Organization.Founder,
// Application.ClientCert and Provider.IssuerUrl all read as "nothing to check"
// and the check reported success by failing to run. A check that CANNOT see a
// thing is not a check that the thing is absent.
//
// So the question is inverted, and the allowlist moves from the dangerous side
// to the safe one. Every scalar an op's input binds from the URL must be a name
// the URL is ALLOWED to carry — the addressing triple, the list filters, the two
// OAuth request parameters. Everything else declares `url:"-"` and lives in the
// body. A field added tomorrow is covered the day it is added, whatever it is
// called and whether or not its type has a Mask.
//
// It also guards a bomb that has not gone off: schema.User carries eighteen
// credential fields with no `url:"-"` at all, and is safe only because every
// input NESTS it under a named `json:"user"` rather than embedding it. Promote
// it and this fails.

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// safe is the URL's whole vocabulary — the names a request may spell in its
// path or query, each because the URL genuinely addresses it:
//
//	owner, name, id      the addressing triple; an item lives at
//	                     /v1/iam/<entity>/{owner}/{name}, and the path is the
//	                     addressing authority the op-invoke authorizer reads.
//	organization,        the scopes a collection is listed within.
//	user, application
//	org                  the scope assume/lookup act in.
//	email                the lookup key for a user read.
//	clientId,            the OAuth request parameters (RFC 6749 4.1.1), which
//	responseType         arrive in the authorize URL by definition.
//	limit, offset,       pagination and search.
//	cursor, p, pageSize, q
//	deleted              orm's soft-delete marker, declared in another module
//	                     and so not IAM's field to tag. It carries no secret and
//	                     no trust decision.
//
// A name earns a place here by being something the URL ADDRESSES, never by
// being convenient. Adding one widens what every client may put in a log line.
var safe = map[string]bool{
	"owner": true, "name": true, "id": true,
	"organization": true, "user": true, "application": true, "org": true,
	"email": true,
	"limit": true, "offset": true, "cursor": true, "p": true, "pageSize": true, "q": true,
	"clientId": true, "responseType": true,
	"deleted": true,
}

// urlName mirrors zip's urlFieldName: `url:` names the field for the URL, else
// its json name stands in, else the Go name. "-" means the binder skips it.
func urlName(f reflect.StructField) string {
	name := func(tag string) string {
		if i := strings.IndexByte(tag, ','); i >= 0 {
			tag = tag[:i]
		}
		if tag == "" {
			return f.Name
		}
		return tag
	}
	if tag, ok := f.Tag.Lookup("url"); ok {
		return name(tag)
	}
	return name(f.Tag.Get("json"))
}

// bindable reports whether zip's setScalar can write this kind. A URL carries
// scalars; a struct, slice, map or pointer field is left alone, which is why a
// nested record is not a URL target.
func bindable(k reflect.Kind) bool {
	switch k {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// field is one wire field and the type that declares it — the owner is what
// carries the Mask, and a promoted field's owner is the embedded type, not the
// input that embeds it.
type field struct {
	owner reflect.Type
	f     reflect.StructField
}

// wire mirrors zip's wireFields: a type's own exported fields plus the promoted
// fields of every UNTAGGED anonymous embedded struct, which is exactly what the
// URL binder walks. A tagged embed is a named object, not a promotion — that is
// encoding/json's rule, so it is this one's too, and it is the whole reason
// schema.User's credentials are out of reach today.
func wire(t reflect.Type, seen map[reflect.Type]bool) []field {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct || seen[t] {
		return nil
	}
	seen[t] = true
	defer delete(seen, t)
	var out []field
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			if _, tagged := f.Tag.Lookup("json"); !tagged {
				out = append(out, wire(f.Type, seen)...)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		out = append(out, field{owner: t, f: f})
	}
	return out
}

// bound reports every URL-bindable scalar of an input type, as
// "Type.Field" -> the name it binds under. It is the instrument; the test
// below points it at the registry, and TestBound_seesAnUntaggedScalar points it
// at a known positive so a silent instrument cannot read as a clean result.
func bound(t reflect.Type) map[string]string {
	out := map[string]string{}
	for _, fl := range wire(t, map[reflect.Type]bool{}) {
		if !bindable(fl.f.Type.Kind()) {
			continue
		}
		if n := urlName(fl.f); n != "-" {
			out[fl.owner.Name()+"."+fl.f.Name] = n
		}
	}
	return out
}

// secretsOf asks the type itself which of its fields are secret: fill every
// string with a sentinel, Mask the value, and report the ones that came back
// changed. A type with no Mask declares no secrets — which is why the check
// above does not rest on it, and why this is used only to hold the SAFE list
// honest.
func secretsOf(t reflect.Type) map[string]bool {
	m, ok := reflect.PointerTo(t).MethodByName("Mask")
	if !ok {
		return nil
	}
	const sentinel = "sentinel-value"
	v := reflect.New(t)
	for i := 0; i < t.NumField(); i++ {
		if f := v.Elem().Field(i); f.Kind() == reflect.String && f.CanSet() {
			f.SetString(sentinel)
		}
	}
	out := m.Func.Call([]reflect.Value{v})
	if len(out) != 1 || out[0].Kind() != reflect.Pointer || out[0].IsNil() {
		return nil
	}
	masked := out[0].Elem()
	secret := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		if masked.Field(i).Kind() == reflect.String && masked.Field(i).String() != sentinel {
			secret[t.Field(i).Name] = true
		}
	}
	return secret
}

// Every registered op, every scalar its input binds from the URL, against the
// one list of names the URL is allowed to carry.
func TestURL_carriesOnlyWhatItAddresses(t *testing.T) {
	app, _ := embedded(t)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	reg := reflect.ValueOf(app.Registry())
	if reg.Len() == 0 {
		t.Fatal("no ops registered — this check cannot run, which is not the same as passing")
	}
	type where struct{ method, path string }
	found := map[string]where{} // "Type.Field binds as name" -> first op that carries it
	for i := 0; i < reg.Len(); i++ {
		op := reg.Index(i).Elem()
		in, _ := op.FieldByName("InType").Interface().(reflect.Type)
		if in == nil {
			continue
		}
		for field, name := range bound(in) {
			if safe[name] {
				continue
			}
			k := fmt.Sprintf("%s binds from the URL as %q", field, name)
			if _, seen := found[k]; !seen {
				found[k] = where{op.FieldByName("Method").String(), op.FieldByName("Path").String()}
			}
		}
	}
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Errorf("%s %s: %s — a URL carries what it addresses; tag the field `url:\"-\"` so it "+
			"binds from the body, or justify the name in `safe`", found[k].method, found[k].path, k)
	}
}

// A NAME ON THE SAFE LIST IS NEVER A DECLARED SECRET.
//
// The safe list is the one place the check above can be widened, so it gets the
// question the old check asked: no type may both Mask a field and carry it under
// a name the URL is allowed to spell.
func TestSafe_namesNoDeclaredSecret(t *testing.T) {
	app, _ := embedded(t)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	reg := reflect.ValueOf(app.Registry())
	secrets := map[reflect.Type]map[string]bool{}
	for i := 0; i < reg.Len(); i++ {
		op := reg.Index(i).Elem()
		in, _ := op.FieldByName("InType").Interface().(reflect.Type)
		if in == nil {
			continue
		}
		for _, fl := range wire(in, map[reflect.Type]bool{}) {
			n := urlName(fl.f)
			if n == "-" || !safe[n] {
				continue
			}
			set, known := secrets[fl.owner]
			if !known {
				set = secretsOf(fl.owner)
				secrets[fl.owner] = set
			}
			if set[fl.f.Name] {
				t.Errorf("%s.%s is masked on the way out but binds from the URL as %q, which the "+
					"safe list permits — the name is wrong for a secret, or the list is",
					fl.owner.Name(), fl.f.Name, n)
			}
		}
	}
}

// THE INSTRUMENT SEES. A check that cannot observe the thing it forbids reports
// success by failing to run, which is how the Mask-derived version passed for
// every type that had no Mask. Point it at a type that is unambiguously in
// violation and require it to say so.
func TestBound_seesAnUntaggedScalar(t *testing.T) {
	type promoted struct {
		Certificate string // no tag at all: binds under its Go name
	}
	type known struct {
		promoted
		Password string `json:"password"`
		Opted    string `json:"opted" url:"-"`
		Nested   struct{ Secret string }
		Owner    string `json:"owner"`
	}
	got := bound(reflect.TypeOf(known{}))
	for _, want := range []struct{ field, name string }{
		{"promoted.Certificate", "Certificate"},
		{"known.Password", "password"},
		{"known.Owner", "owner"},
	} {
		if got[want.field] != want.name {
			t.Errorf("bound() missed %s — it should bind as %q, got %q", want.field, want.name, got[want.field])
		}
	}
	if n, ok := got["known.Opted"]; ok {
		t.Errorf(`bound() reported a url:"-" field as bindable: %q`, n)
	}
	if n, ok := got["known.Nested"]; ok {
		t.Errorf("bound() reported a struct field as a URL target: %q", n)
	}
}

// EVERY PATH PARAMETER STILL HAS A FIELD TO BIND INTO.
//
// `url:"-"` opts a field out of ONE binder, and that binder serves both halves of
// the URL: zip calls bindURL for the query and again for the path params. So the
// tag that keeps a body field out of the query would also, on the wrong field,
// silently unaddress a route — PUT /v1/iam/certs/{owner}/{name} would decode a
// Cert with no owner and no name, and the op-invoke authorizer, which reads the
// target off that same decoded value, would judge the empty one.
//
// Nothing about that fails loudly, so it is asserted directly: for every op whose
// pattern names a parameter, the input must carry a field that binds under that
// name. This is the complement of the check above — one says nothing extra binds
// from the URL, this says everything the URL addresses still does.
func TestPathParams_bindIntoAField(t *testing.T) {
	app, _ := embedded(t)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	reg := reflect.ValueOf(app.Registry())
	params := 0
	for i := 0; i < reg.Len(); i++ {
		op := reg.Index(i).Elem()
		in, _ := op.FieldByName("InType").Interface().(reflect.Type)
		if in == nil {
			continue
		}
		path := op.FieldByName("Path").String()
		names := map[string]bool{}
		for _, name := range bound(in) {
			names[strings.ToLower(name)] = true
		}
		for _, seg := range strings.Split(path, "/") {
			if !strings.HasPrefix(seg, ":") {
				continue
			}
			params++
			if p := strings.ToLower(seg[1:]); !names[p] {
				t.Errorf("%s %s: the path names %q and the input binds no field under it — "+
					"the route addresses a row the handler will never see",
					op.FieldByName("Method").String(), path, seg)
			}
		}
	}
	if params == 0 {
		t.Fatal("no path parameters found — this check cannot run, which is not the same as passing")
	}
	t.Logf("%d path parameters bind", params)
}

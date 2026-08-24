// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package routes_test

// WHAT A READER CANNOT SEE, A URL CANNOT CARRY.
//
// schema.Mask is the ONE declaration of which fields are secret — pkg/schema/mask.go
// says so, and CarrySecretsFrom already reads it in the other direction: what a
// reader cannot see, a writer cannot state. This reads it in a third: a secret must
// not be settable from the URL.
//
// It matters because zip binds a typed op's scalars from the query string on EVERY
// method, and binds the query AFTER the body — so a secret field with no `url:"-"`
// is not merely also-settable from the URL, it OVERRIDES what the body sent. A URL
// is the part of a request that gets written down: access and proxy logs, browser
// history, the Referer of whatever the answer links to.
//
// The set is DERIVED, never listed here: the check fills a value, masks it, and
// takes the fields that changed. A secret added to Mask is therefore covered the
// day it is added, and a list that could drift out of step with Mask never exists.

import (
	"reflect"
	"strings"
	"testing"
)

// urlName mirrors zip's urlFieldName: `url:` names the field for the URL, else its
// json name stands in. "-" means the binder skips it.
func urlName(f reflect.StructField) string {
	if tag, ok := f.Tag.Lookup("url"); ok {
		return strings.Split(tag, ",")[0]
	}
	if tag, ok := f.Tag.Lookup("json"); ok {
		if n := strings.Split(tag, ",")[0]; n != "" {
			return n
		}
	}
	return f.Name
}

// field is one wire field and the type that declares it — the owner is what
// carries the Mask, and a promoted field's owner is the embedded type, not the
// input that embeds it.
type field struct {
	owner reflect.Type
	f     reflect.StructField
}

// wire mirrors zip's wireFields: a type's own fields plus the promoted fields of
// every anonymous embedded struct, which is exactly what the URL binder walks.
func wire(t reflect.Type, seen map[reflect.Type]bool) []field {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct || seen[t] {
		return nil
	}
	seen[t] = true
	var out []field
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			out = append(out, wire(f.Type, seen)...)
			continue
		}
		out = append(out, field{owner: t, f: f})
	}
	return out
}

// secretsOf asks the type itself which of its fields are secret: fill every string
// with a sentinel, Mask the value, and report the ones that came back changed. A
// type with no Mask declares no secrets.
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

// Every registered op, every field its input binds, against the secret set the
// field's own type declares.
func TestSecrets_neverBindFromTheURL(t *testing.T) {
	app, _ := embedded(t)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	reg := reflect.ValueOf(app.Registry())
	if reg.Len() == 0 {
		t.Fatal("no ops registered — this check cannot run, which is not the same as passing")
	}
	secrets := map[reflect.Type]map[string]bool{}
	for i := 0; i < reg.Len(); i++ {
		op := reg.Index(i).Elem()
		in, _ := op.FieldByName("InType").Interface().(reflect.Type)
		if in == nil {
			continue
		}
		for _, fl := range wire(in, map[reflect.Type]bool{}) {
			set, known := secrets[fl.owner]
			if !known {
				set = secretsOf(fl.owner)
				secrets[fl.owner] = set
			}
			if !set[fl.f.Name] || urlName(fl.f) == "-" {
				continue
			}
			t.Errorf("%s %s: %s.%s is masked on the way out but binds from the URL as %q — tag it `url:\"-\"`",
				op.FieldByName("Method").String(), op.FieldByName("Path").String(),
				fl.owner.Name(), fl.f.Name, urlName(fl.f))
		}
	}
}

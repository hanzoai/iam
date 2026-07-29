// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package scim

// A discovery document that describes attributes the handler does not bind — or
// omits ones it does — is worse than no discovery document: an IdP configures
// against it and the mismatch surfaces as silently-dropped fields in production.
// This test makes that drift a build failure. It is in-package on purpose: it
// reflects over the unexported wire struct, which is the authority on what the
// handler binds.

import (
	"reflect"
	"strings"
	"testing"
)

// envelope attributes are RFC 7643 §3.1 COMMON attributes (id, externalId, meta,
// schemas) and the extension container — they belong to every SCIM resource, not
// to the User schema's own attribute list, so they are legitimately absent from it.
var envelope = map[string]bool{
	"schemas": true, "id": true, "meta": true, "externalId": true,
	schemaHanzoUserExt: true,
}

// jsonNames returns the JSON field names of a struct type.
func jsonNames(t reflect.Type) []string {
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, strings.Split(tag, ",")[0])
	}
	return out
}

func TestSchema_matchesWireStruct(t *testing.T) {
	declared := map[string]attribute{}
	for _, a := range userAttributes {
		declared[a.Name] = a
	}

	wire := map[string]bool{}
	for _, n := range jsonNames(reflect.TypeOf(scimUser{})) {
		wire[n] = true
		if envelope[n] {
			continue
		}
		if _, ok := declared[n]; !ok {
			t.Errorf("scimUser binds %q but /Schemas does not declare it — an IdP cannot discover it", n)
		}
	}
	for name := range declared {
		if !wire[name] {
			t.Errorf("/Schemas declares %q but scimUser does not bind it — an IdP will send a field that is dropped", name)
		}
	}
}

// TestSchema_subAttributesMatchWire pins the complex attributes' sub-fields to the
// Go structs that bind them, for the same reason as the top level.
func TestSchema_subAttributesMatchWire(t *testing.T) {
	for _, tc := range []struct {
		attr string
		typ  reflect.Type
	}{
		{"name", reflect.TypeOf(scimName{})},
		{"emails", reflect.TypeOf(scimMultiValued{})},
		{"addresses", reflect.TypeOf(scimAddress{})},
	} {
		var subs []attribute
		for _, a := range userAttributes {
			if a.Name == tc.attr {
				subs = a.SubAttributes
			}
		}
		if subs == nil {
			t.Errorf("%s: no sub-attributes declared", tc.attr)
			continue
		}
		declared := map[string]bool{}
		for _, s := range subs {
			declared[s.Name] = true
		}
		for _, n := range jsonNames(tc.typ) {
			if !declared[n] {
				t.Errorf("%s: wire sub-field %q is not declared in /Schemas", tc.attr, n)
			}
		}
	}
}

// TestSchema_privilegedAttributesAreNotWritable is the mutability pin. Two
// attributes must never be advertised as writable, because the handler must never
// honour a client-supplied value for them:
//
//   - userType — schema.User.Type is the identity-class discriminator
//     (service-account); a writable userType is an identity-class escalation.
//   - password — write-only credential; `returned` must be "never" so no
//     projection can be widened into echoing it.
func TestSchema_privilegedAttributesAreNotWritable(t *testing.T) {
	byName := map[string]attribute{}
	for _, a := range userAttributes {
		byName[a.Name] = a
	}
	if got := byName["userType"].Mutability; got != "readOnly" {
		t.Errorf("userType mutability = %q, want readOnly — it is the service-account discriminator", got)
	}
	if got := byName["password"].Returned; got != "never" {
		t.Errorf("password returned = %q, want never", got)
	}
	if got := byName["password"].Mutability; got != "writeOnly" {
		t.Errorf("password mutability = %q, want writeOnly", got)
	}
}

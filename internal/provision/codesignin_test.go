// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package provision

import (
	"encoding/json"
	"strings"
	"testing"
)

// An undeclared setting must be OMITTED from the body, not sent as false.
//
// This is the whole reason the field is a pointer. The upsert applies any value
// it receives, so a plain bool would send false on every converge of every app
// whose document never mentions code sign-in — silently switching the method off
// across the fleet on the next unrelated reconcile.
func TestCodeSigninOmittedWhenUndeclared(t *testing.T) {
	body, err := json.Marshal(Client{Organization: "hanzo", Name: "hanzo-id"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "enableCodeSignin") {
		t.Errorf("an undeclared setting reached the wire: %s", body)
	}
}

// Declaring it — either way — must travel, so a document can turn the method on
// AND can deliberately turn it back off.
func TestCodeSigninTravelsWhenDeclared(t *testing.T) {
	for _, want := range []bool{true, false} {
		v := want
		body, err := json.Marshal(Client{Organization: "hanzo", Name: "hanzo-id", EnableCodeSignin: &v})
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got["enableCodeSignin"] != want {
			t.Errorf("enableCodeSignin = %v, want %v (body %s)", got["enableCodeSignin"], want, body)
		}
	}
}

// The document field reaches the wire field. Two names for one setting is how a
// declaration silently stops taking effect.
func TestCodeSigninCarriesFromDocumentToClient(t *testing.T) {
	on := true
	doc := `
orgs:
  - name: hanzo
    displayName: Hanzo
    homepage: https://hanzo.ai
    apps:
      - app: id
        type: spa
        hosts: [hanzo.id]
        cert: cert-hanzo
        codeSignin: true
`
	parsed, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	app := parsed.Orgs[0].Apps[0]
	if app.CodeSignin == nil || *app.CodeSignin != on {
		t.Fatalf("document codeSignin did not parse: %v", app.CodeSignin)
	}

	clients, err := Derive(parsed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("derived %d clients, want 1", len(clients))
	}
	if c := clients[0]; c.EnableCodeSignin == nil || !*c.EnableCodeSignin {
		t.Errorf("codeSignin did not reach the registration: %v", c.EnableCodeSignin)
	}
}

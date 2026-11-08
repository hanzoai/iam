// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package provision

import (
	"encoding/json"
	"strings"
	"testing"
)

// An app that says nothing about where it signs in sends nothing, so the converge
// leaves what it has.
func TestSigninOmittedWhenUndeclared(t *testing.T) {
	body, err := json.Marshal(Client{Organization: "hanzo", Name: "hanzo-cli"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "signinUrl") {
		t.Errorf("an undeclared setting reached the wire: %s", body)
	}
}

// The document's `signin` reaches the registration's signinUrl, for the app that
// declared it and for no other app of the org.
func TestSigninCarriesFromDocumentToClient(t *testing.T) {
	doc := `
orgs:
  - name: hanzo
    displayName: Hanzo
    homepage: https://hanzo.ai
    apps:
      - app: cli
        type: cli
        signin: https://hanzo.ai/login
      - app: id
        type: spa
        hosts: [hanzo.id]
`
	parsed, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	clients, err := Derive(parsed)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	got := map[string]*string{}
	for _, c := range clients {
		got[c.Name] = c.SigninUrl
	}
	if p := got["hanzo-cli"]; p == nil || *p != "https://hanzo.ai/login" {
		t.Errorf("hanzo-cli signinUrl = %v", p)
	}
	if got["hanzo-id"] != nil {
		t.Errorf("hanzo-id declared none and sent %q", *got["hanzo-id"])
	}
}

// A signin that could never be an address fails the plan a reviewer reads.
func TestSigninIsJudgedAtDerive(t *testing.T) {
	doc := `
orgs:
  - name: hanzo
    displayName: Hanzo
    homepage: https://hanzo.ai
    apps:
      - app: cli
        type: cli
        signin: http://hanzo.ai/login
`
	parsed, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := Derive(parsed); err == nil {
		t.Fatal("a cleartext signin was derived")
	}
}

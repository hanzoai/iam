// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package e2e_test

// One shape ran through the whole entity surface: a write authorized its own
// (Owner, Name) and then bound every other field verbatim — including the fields
// that NAME something else. The row said where it was filed; the field said what it
// reached. forge_test.go drives the chain that was live. This drives the rest of
// the shape, over the real router, as an organization admin who is never a
// SuperAdmin: every field that names a platform row is refused, and the ordinary
// write beside it still lands.

import (
	"encoding/json"
	"strings"
	"testing"
)

// refusals are the writes that name something the caller may not reach.
func TestAuthority_aTenantCannotNameAPlatformRow(t *testing.T) {
	e := boot(t)
	seedUser(t, e.db, "hanzo", "boss", "boss@hanzo.ai", "pw", true) // org admin, never super
	boss := e.mint(t, "hanzo/boss")

	for _, tc := range []struct{ name, method, path, body string }{
		// A grant's subjects: the people it is evaluated for.
		{"permission names a platform person", "POST", "/v1/iam/permissions",
			`{"owner":"hanzo","name":"forge","users":["admin/root"]}`},
		{"permission names a platform role", "POST", "/v1/iam/permissions",
			`{"owner":"hanzo","name":"forge2","roles":["admin/operators"]}`},
		// A role's members.
		{"role bundles a platform person", "POST", "/v1/iam/roles",
			`{"owner":"hanzo","name":"forge","users":["admin/root"]}`},
		// A provider's signing cert: the key a federated assertion is verified with.
		{"provider names the platform signing cert", "POST", "/v1/iam/providers",
			`{"owner":"hanzo","name":"forge","type":"SAML","cert":"` + kid + `"}`},
		// An invitation's referents: what whoever redeems it arrives with.
		{"invitation names a platform application", "POST", "/v1/iam/invitations",
			`{"owner":"hanzo","name":"forge","application":"admin/hanzo-console"}`},
		{"invitation names a platform group", "POST", "/v1/iam/invitations",
			`{"owner":"hanzo","name":"forge2","signupGroup":"admin/operators"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st, body := e.req(t, tc.method, tc.path, boss, tc.body, "application/json"); st != 403 {
				t.Fatalf("status=%d, want 403; body=%s", st, body)
			}
		})
	}
}

// The same organization admin does its ordinary work unhindered: every one of
// those writes lands when it names its OWN organization. A gate that refused these
// would have broken the surface rather than closed it.
func TestAuthority_aTenantStillWritesItsOwn(t *testing.T) {
	e := boot(t)
	seedUser(t, e.db, "hanzo", "boss", "boss@hanzo.ai", "pw", true)
	boss := e.mint(t, "hanzo/boss")

	for _, tc := range []struct{ name, method, path, body string }{
		{"permission grants to its own people", "POST", "/v1/iam/permissions",
			`{"owner":"hanzo","name":"editor","users":["hanzo/alice"],"actions":["read"]}`},
		{"role bundles its own people", "POST", "/v1/iam/roles",
			`{"owner":"hanzo","name":"engineers","users":["hanzo/alice"]}`},
		{"provider names no signing cert", "POST", "/v1/iam/providers",
			`{"owner":"hanzo","name":"github","type":"GitHub"}`},
		{"invitation names its own application", "POST", "/v1/iam/invitations",
			`{"owner":"hanzo","name":"join","application":"console","email":"new@hanzo.ai"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st, body := e.req(t, tc.method, tc.path, boss, tc.body, "application/json"); st != 200 {
				t.Fatalf("status=%d, want 200; body=%s", st, body)
			}
		})
	}
}

// Two fields are not refused but SERVER-OWNED: whatever a request sends, what
// lands is what the server decided. A refusal would be the wrong answer for
// either — a request may ask to sign someone in, or to file a project; it just
// does not get to choose the cookie or the organization.
func TestAuthority_theServerOwnsWhatTheRequestCannotChoose(t *testing.T) {
	e := boot(t)
	seedUser(t, e.db, "hanzo", "boss", "boss@hanzo.ai", "pw", true)
	boss := e.mint(t, "hanzo/boss")

	// A cookie id is minted by the sign-in. A chosen one names a browser that never
	// signed in, and the list is what a presented cookie is checked against.
	st, body := e.req(t, "POST", "/v1/iam/sessions", boss,
		`{"owner":"hanzo","name":"alice","application":"hanzo-console","sessionId":["chosen-cookie"]}`,
		"application/json")
	if st != 200 {
		t.Fatalf("recording a sign-in: status=%d, want 200; body=%s", st, body)
	}
	if strings.Contains(body, "chosen-cookie") {
		t.Fatalf("a request chose the cookie id: %s", body)
	}

	// A project belongs to the organization that owns it, whatever it was asked to say.
	st, body = e.req(t, "POST", "/v1/iam/projects", boss,
		`{"owner":"hanzo","name":"beta","organization":"admin"}`, "application/json")
	if st != 200 {
		t.Fatalf("filing a project: status=%d, want 200; body=%s", st, body)
	}
	var project map[string]any
	if err := json.Unmarshal([]byte(body), &project); err != nil {
		t.Fatalf("decode project: %v; body=%s", err, body)
	}
	if got := project["organization"]; got != "hanzo" {
		t.Fatalf("project organization = %v, want the owner hanzo; body=%s", got, body)
	}
}

// A SuperAdmin is the one scope that reaches across organizations, so none of the
// refusals above is a wall in front of the platform's own work.
func TestAuthority_aSuperAdminStillReachesAcross(t *testing.T) {
	e := boot(t)
	root := e.mint(t, "admin/root")

	for _, tc := range []struct{ name, path, body string }{
		{"platform grant", "/v1/iam/permissions",
			`{"owner":"hanzo","name":"platform","users":["admin/root"]}`},
		{"platform role", "/v1/iam/roles",
			`{"owner":"hanzo","name":"operators","users":["admin/root"]}`},
		{"platform signing cert on a provider", "/v1/iam/providers",
			`{"owner":"hanzo","name":"idp","type":"SAML","cert":"` + kid + `"}`},
		{"invitation through the platform console", "/v1/iam/invitations",
			`{"owner":"hanzo","name":"platform","application":"admin/hanzo-console"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st, body := e.req(t, "POST", tc.path, root, tc.body, "application/json"); st != 200 {
				t.Fatalf("status=%d, want 200; body=%s", st, body)
			}
		})
	}
}

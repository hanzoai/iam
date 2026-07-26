// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz_test

// The Casdoor verb surface, driven end to end through the REAL mounted router as
// a REAL confidential client (client_secret_basic) — the exact principal shape the
// live 403 was measured with, and the one a SuperAdmin bearer would mask, because
// p.Super short-circuits the whole policy.
//
// The contract under test is PARITY: a verb path and its REST twin must return the
// SAME status for the SAME principal and the SAME body. That is asserted directly
// rather than against hard-coded codes, so the test cannot drift into blessing a
// grant the REST surface does not make. A 403 is the authorization refusal; any
// other status (400 "owner and name are required", 200) means authorization PASSED
// and the handler took over — the same 400-vs-403 signal used to probe production,
// and it creates nothing either way.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// seedApp registers a confidential client: an application row with a clientId and
// secret, OWNED by `owner` (the owner-pin in cap.go grants a capability only when
// that is a reserved platform signing owner) and SERVING organization `org`.
func seedApp(t *testing.T, db orm.DB, owner, name, org, clientId, secret string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name = owner, name
	a.Organization = org
	a.ClientId, a.ClientSecret = clientId, secret
	a.SetId(owner + "/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed application %s/%s: %v", owner, name, err)
	}
}

// doBasic issues one request authenticated as a confidential client — RFC 6749
// §2.3.1 client_secret_basic, the transport every live server-side consumer uses.
func (h *harness) doBasic(t *testing.T, method, path, clientId, secret string, body any) int {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(clientId, secret)
	resp, err := h.app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// The repair, and its bound, on the wire. Each case fires the SAME body at a verb
// path and at its REST twin as the SAME confidential client, and requires the two
// statuses to agree — then requires that agreement to be on the expected side of
// 403, so a pair that agreed by being BOTH broken cannot pass.
func TestCompatVerbParityOverHTTP(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")
	t.Setenv("IAM_USER_ADMIN_APPS", "hanzo-console")

	h := newHarness(t)
	// The platform console: admin-OWNED (passes the owner-pin) and serving the admin
	// org, exactly like the live hanzo-console row.
	seedApp(t, h.db, "admin", "hanzo-console", "admin", "console-id", "console-secret")
	// A tenant-owned app that registers the SAME allow-listed NAME — the spoofing
	// vector the owner-pin exists to defeat. It must hold nothing on the verb surface.
	seedApp(t, h.db, "hanzo", "hanzo-console", "hanzo", "spoof-id", "spoof-secret")

	// The two surfaces do not share a body SHAPE for users: the Casdoor verb posts a
	// flat user (compat.userBody embeds schema.User), while the REST twin nests it
	// under `user` (users.CreateInput, whose AuthzTarget reads in.User.Owner). Each
	// side must therefore be sent the shape it binds, or the comparison is between an
	// addressed target and an empty one — which is a different authorization question.
	// restBody carries that shape; nil means the two bodies are identical.
	user := func(owner, name string) any {
		return map[string]any{"user": map[string]any{"owner": owner, "name": name}}
	}

	cases := []struct {
		name       string
		verb, rest string
		body       any
		restBody   any
		allowed    bool // true: authorization must PASS on both (non-403)
	}{
		// THE OUTAGE. cloud's signup fallback posts add-organization; an org row is
		// filed under the reserved admin owner, so this is the reserved-owner branch,
		// which only the organizations entity may enter. It must pass, exactly as its
		// REST twin does — an empty body then fails validation, creating nothing.
		{"add-organization is repaired", "/v1/iam/add-organization", "/v1/iam/organizations", map[string]any{}, nil, true},
		{"add-organization at admin owner", "/v1/iam/add-organization", "/v1/iam/organizations",
			map[string]any{"owner": "admin", "name": "acme"}, nil, true},
		{"update-organization", "/v1/iam/update-organization", "/v1/iam/organizations/update",
			map[string]any{"owner": "admin", "name": "hanzo"}, nil, true},

		// The move-user leg of the same signup, in the TENANT org where it belongs.
		{"update-user in tenant org", "/v1/iam/update-user", "/v1/iam/users/update",
			map[string]any{"owner": "hanzo", "name": "alice"}, user("hanzo", "alice"), true},
		{"add-user in tenant org", "/v1/iam/add-user", "/v1/iam/users",
			map[string]any{"owner": "hanzo", "name": "newbie"}, user("hanzo", "newbie"), true},

		// THE BOUND. A user under a RESERVED owner stays refused: entity "users" never
		// enters the reserved-owner exception, so the capability is never consulted.
		// This is the gate that keeps platform identities and signing material
		// SuperAdmin-only, and the repair must not have loosened it.
		{"add-user at admin owner denied", "/v1/iam/add-user", "/v1/iam/users",
			map[string]any{"owner": "admin", "name": "backdoor"}, user("admin", "backdoor"), false},
		{"add-user at built-in owner denied", "/v1/iam/add-user", "/v1/iam/users",
			map[string]any{"owner": "built-in", "name": "backdoor"}, user("built-in", "backdoor"), false},
		{"add-user at app owner denied", "/v1/iam/add-user", "/v1/iam/users",
			map[string]any{"owner": "app", "name": "backdoor"}, user("app", "backdoor"), false},
		{"update-user at admin owner denied", "/v1/iam/update-user", "/v1/iam/users/update",
			map[string]any{"owner": "admin", "name": "root"}, user("admin", "root"), false},

		// An unmapped entity grants a confidential client NOTHING, verb or REST —
		// providers and roles carry no capability, so both sides refuse.
		{"add-provider denied", "/v1/iam/add-provider", "/v1/iam/providers",
			map[string]any{"owner": "hanzo", "name": "p"}, nil, false},
		{"add-role denied", "/v1/iam/add-role", "/v1/iam/roles",
			map[string]any{"owner": "hanzo", "name": "r"}, nil, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			restBody := c.restBody
			if restBody == nil {
				restBody = c.body
			}
			verb := h.doBasic(t, "POST", c.verb, "console-id", "console-secret", c.body)
			rest := h.doBasic(t, "POST", c.rest, "console-id", "console-secret", restBody)
			if (verb == 403) != (rest == 403) {
				t.Fatalf("PARITY BROKEN: %s -> %d but %s -> %d", c.verb, verb, c.rest, rest)
			}
			if c.allowed && verb == 403 {
				t.Fatalf("%s -> 403; authorization must pass (its twin %s -> %d)", c.verb, c.rest, rest)
			}
			if !c.allowed && verb != 403 {
				t.Fatalf("%s -> %d; authorization must refuse", c.verb, verb)
			}
		})
	}

	// Nothing the refused calls named was persisted — the real property, not a code.
	for _, owner := range []string{"admin", "built-in", "app"} {
		if h.userExists(t, owner, "backdoor") {
			t.Fatalf("a refused add-user persisted %s/backdoor", owner)
		}
	}

	// The spoofing app holds nothing on the repaired surface: same allow-listed NAME,
	// non-signing owner, so every capability is denied and the aliases stay inert.
	for _, p := range []string{"/v1/iam/add-organization", "/v1/iam/add-user", "/v1/iam/update-user"} {
		if got := h.doBasic(t, "POST", p, "spoof-id", "spoof-secret", map[string]any{"owner": "admin", "name": "x"}); got != 403 {
			t.Fatalf("%s -> %d for a tenant-owned app spoofing the console name; want 403", p, got)
		}
	}
}

// The compat READ verbs, same parity contract on the Guard's side of the seam
// (a GET's target rides the query string, so it is authorized in the Guard, not at
// the op-invoke hook — a different code path from the writes above).
func TestCompatReadParityOverHTTP(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")
	t.Setenv("IAM_USER_ADMIN_APPS", "hanzo-console")

	h := newHarness(t)
	seedApp(t, h.db, "admin", "hanzo-console", "admin", "console-id", "console-secret")

	cases := []struct {
		name       string
		verb, rest string
		allowed    bool
	}{
		{"get-organizations", "/v1/iam/get-organizations?owner=admin", "/v1/iam/organizations?owner=admin", true},
		{"get-users in tenant org", "/v1/iam/get-users?owner=hanzo", "/v1/iam/users?owner=hanzo", true},
		{"get-global-users in tenant org", "/v1/iam/get-global-users?owner=hanzo", "/v1/iam/users?owner=hanzo", true},
		// A users read under a RESERVED owner stays refused — entity "users" does not
		// enter the reserved-owner exception, so the admin org's roster is super-only.
		{"get-users at admin owner denied", "/v1/iam/get-users?owner=admin", "/v1/iam/users?owner=admin", false},
		// Signing material is never readable by a confidential client, verb or REST.
		{"get-certs denied", "/v1/iam/get-certs?owner=admin", "/v1/iam/certs?owner=admin", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verb := h.doBasic(t, "GET", c.verb, "console-id", "console-secret", nil)
			rest := h.doBasic(t, "GET", c.rest, "console-id", "console-secret", nil)
			if (verb == 403) != (rest == 403) {
				t.Fatalf("PARITY BROKEN: %s -> %d but %s -> %d", c.verb, verb, c.rest, rest)
			}
			if c.allowed && verb == 403 {
				t.Fatalf("%s -> 403; authorization must pass (its twin %s -> %d)", c.verb, c.rest, rest)
			}
			if !c.allowed && verb != 403 {
				t.Fatalf("%s -> %d; authorization must refuse", c.verb, verb)
			}
		})
	}
}

// The compound reads are NOT organization reads. get-organization-projects and
// get-organization-workspaces name their parent org but address the child
// collection; if either resolved to "organizations" it would inherit the
// CapOrgAdmin grant. Here the console HOLDS CapOrgAdmin, so a mis-resolution would
// show up as a pass on a collection it has no capability for — and the org-owned
// projects listing must stay pinned to the caller's own tenant regardless.
func TestCompoundReadsAreNotOrganizationReads(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")
	h := newHarness(t)
	seedApp(t, h.db, "admin", "hanzo-console", "admin", "console-id", "console-secret")

	for _, p := range []string{
		"/v1/iam/get-organization-projects?organization=orgb",
		"/v1/iam/get-organization-workspaces?organization=orgb",
	} {
		status, body := h.doBasicBody(t, "GET", p, "console-id", "console-secret")
		// The handler owner-scopes through authz.Scope, which pins a non-super to its
		// OWN org — so a request naming another tenant can never return that tenant's
		// rows, whatever the Guard decided.
		if status == 200 && bytes.Contains([]byte(body), []byte(`"owner":"orgb"`)) {
			t.Fatalf("%s leaked another tenant's rows: %s", p, body)
		}
	}
}

// doBasicBody is doBasic plus the response body.
func (h *harness) doBasicBody(t *testing.T, method, path, clientId, secret string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "hanzo.id"
	req.SetBasicAuth(clientId, secret)
	resp, err := h.app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// A REGULAR (non-admin) user reaches the repaired read verbs exactly as it reaches
// their REST twins — and that exposes a PRE-EXISTING defect this change makes more
// reachable, so it is pinned here rather than left to be discovered.
//
// authorize()'s self-service clause is `GET && entity == "users" && name == p.User`.
// It was written for a SINGLE-row read, but the Guard applies it to whatever the
// query names — so a member who spells its OWN name at a LIST route satisfies the
// clause, and the list handler then ignores `name` and returns the whole roster.
// That is live on /v1/iam/users today; resolving get-users to "users" (which REST
// parity requires) gives the verb aliases the same reach.
//
// The assertion is PARITY, not blessing: verb and REST must agree. If the clause is
// later bound to single-row reads — the correct fix, and a change to authorize(),
// not to entityOf — both sides tighten together and this test still passes.
func TestRegularUserReadParityAndTheSelfClauseWidth(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice") // regular member of hanzo: not admin, not super

	for _, c := range []struct{ verb, rest string }{
		{"/v1/iam/get-users?owner=hanzo&name=alice", "/v1/iam/users?owner=hanzo&name=alice"},
		{"/v1/iam/get-users?owner=hanzo", "/v1/iam/users?owner=hanzo"},
		{"/v1/iam/get-users?owner=orgb&name=alice", "/v1/iam/users?owner=orgb&name=alice"},
	} {
		verb := h.do(t, "GET", c.verb, alice, nil)
		rest := h.do(t, "GET", c.rest, alice, nil)
		if (verb == 403) != (rest == 403) {
			t.Fatalf("PARITY BROKEN for a regular user: %s -> %d but %s -> %d", c.verb, verb, c.rest, rest)
		}
	}

	// Cross-tenant stays refused on both — the tenant rule, untouched by this change.
	if got := h.do(t, "GET", "/v1/iam/get-users?owner=orgb&name=alice", alice, nil); got != 403 {
		t.Fatalf("regular user cross-tenant list -> %d; want 403", got)
	}
}

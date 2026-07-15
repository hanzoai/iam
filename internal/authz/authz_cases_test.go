// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz_test

import (
	"net/http"
	"testing"
	"time"
)

// The eight required cases, each through the real mounted router. Sub names map
// to seeded principals: admin/root = SuperAdmin, hanzo/boss = org admin,
// hanzo/alice = regular user, orgb/bob = a foreign org's admin.

// 1. An unauthenticated CRUD write is refused before any handler runs.
func TestUnauthenticatedWriteIs401(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name, method, path string
		body               any
	}{
		{"create user", "POST", "/v1/iam/users", user("hanzo", "x")},
		{"write cert", "POST", "/v1/iam/certs", cert("admin", signingKid)},
		{"register app", "POST", "/v1/iam/application", map[string]any{"owner": "admin", "name": "x"}},
		{"delete user", "POST", "/v1/iam/users/delete", map[string]any{"owner": "hanzo", "name": "alice"}},
		{"update cert", "POST", "/v1/iam/certs/update", cert("admin", signingKid)},
		{"create org", "POST", "/v1/iam/organizations", map[string]any{"owner": "admin", "name": "x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.do(t, c.method, c.path, "", c.body); got != http.StatusUnauthorized {
				t.Fatalf("%s %s no bearer = %d, want 401", c.method, c.path, got)
			}
		})
	}
}

// 2. A valid principal in orgB writing an orgA-owned entity is refused (tenant
// isolation): the target org is bound to the principal, never the body.
func TestCrossOrgWriteIs403(t *testing.T) {
	h := newHarness(t)
	bob := h.token(t, "orgb/bob") // org admin, but of orgb
	cases := []struct {
		name, method, path string
		body               any
	}{
		{"create user in hanzo", "POST", "/v1/iam/users", user("hanzo", "mole")},
		{"update user in hanzo", "POST", "/v1/iam/users/update", user("hanzo", "alice")},
		{"delete user in hanzo", "POST", "/v1/iam/users/delete", map[string]any{"owner": "hanzo", "name": "alice"}},
		{"create role in hanzo", "POST", "/v1/iam/roles", map[string]any{"owner": "hanzo", "name": "r"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.do(t, c.method, c.path, bob, c.body); got != http.StatusForbidden {
				t.Fatalf("orgb principal %s %s = %d, want 403", c.method, c.path, got)
			}
		})
	}
}

// 3. THE poisoning gate. A non-SuperAdmin — org admin OR regular user OR a
// built-in-org member — writing an admin/built-in-owned signing cert is refused.
// Every cert write verb is covered, and the update/delete target the LIVE
// signing cert, so a bypass would truly overwrite the platform key.
func TestSigningCertPoisoningIs403(t *testing.T) {
	h := newHarness(t)
	principals := map[string]string{
		"org admin (hanzo/boss)":         h.token(t, "hanzo/boss"),
		"regular user (hanzo/alice)":     h.token(t, "hanzo/alice"),
		"built-in member (built-in/svc)": h.token(t, "built-in/svc"),
	}
	writes := []struct {
		name, path string
		body       any
	}{
		{"create admin cert", "/v1/iam/certs", cert("admin", "cert-forge")},
		{"overwrite live admin cert", "/v1/iam/certs/update", cert("admin", signingKid)},
		{"delete live admin cert", "/v1/iam/certs/delete", map[string]any{"owner": "admin", "name": signingKid}},
		{"create built-in cert", "/v1/iam/certs", cert("built-in", "cert-forge")},
		{"overwrite built-in cert", "/v1/iam/certs/update", cert("built-in", "anything")},
	}
	for who, tok := range principals {
		for _, w := range writes {
			t.Run(who+" "+w.name, func(t *testing.T) {
				if got := h.do(t, "POST", w.path, tok, w.body); got != http.StatusForbidden {
					t.Fatalf("%s writing %s = %d, want 403 (poisoning gate)", who, w.path, got)
				}
			})
		}
	}
}

// 4. A SuperAdmin (org == admin) may write the admin signing cert and act across
// any org. The guard admits it; the handler then succeeds (2xx). The rotation
// case overwrites the LIVE signing cert with a complete body (key preserved) —
// the legitimate operation the poisoning gate exists to reserve to SuperAdmins.
func TestSuperAdminWritesAdminCertAndCrossOrg(t *testing.T) {
	h := newHarness(t)
	root := h.token(t, "admin/root")
	rotate := map[string]any{
		"owner": "admin", "name": signingKid,
		"cryptoAlgorithm": "RS256", "privateKey": rsaKeyToPEM(t, h.key),
	}
	cases := []struct {
		name, method, path string
		body               any
	}{
		{"create a new admin signing cert", "POST", "/v1/iam/certs", cert("admin", "cert-fresh")},
		{"rotate the live admin signing cert", "POST", "/v1/iam/certs/update", rotate},
		{"create a user in any org", "POST", "/v1/iam/users", user("hanzo", "hire-by-root")},
		{"create a user in another org", "POST", "/v1/iam/users", user("orgb", "hire-by-root")},
		{"register an admin-owned app", "POST", "/v1/iam/application", map[string]any{"owner": "admin", "name": "root-app", "clientId": "root-app"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := h.do(t, c.method, c.path, root, c.body)
			if got < 200 || got >= 300 {
				t.Fatalf("SuperAdmin %s %s = %d, want 2xx", c.method, c.path, got)
			}
		})
	}
}

// 5. An org admin manages its OWN org's users and apps (2xx) but not another
// org's (403). This is the org-admin tier: org-scoped, never cross-tenant.
func TestOrgAdminManagesOwnOrgOnly(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	allow := []struct {
		name, method, path string
		body               any
	}{
		{"create user in own org", "POST", "/v1/iam/users", user("hanzo", "newhire")},
		{"update self org's user", "POST", "/v1/iam/users/update", user("hanzo", "alice")},
		{"register app in own org", "POST", "/v1/iam/application", map[string]any{"owner": "hanzo", "name": "hanzo-app", "clientId": "hanzo-app"}},
	}
	for _, c := range allow {
		t.Run("allow/"+c.name, func(t *testing.T) {
			got := h.do(t, c.method, c.path, boss, c.body)
			if got < 200 || got >= 300 {
				t.Fatalf("org admin %s %s (own org) = %d, want 2xx", c.method, c.path, got)
			}
		})
	}

	deny := []struct {
		name, method, path string
		body               any
	}{
		{"create user in another org", "POST", "/v1/iam/users", user("orgb", "mole")},
		{"register app in another org", "POST", "/v1/iam/application", map[string]any{"owner": "orgb", "name": "x", "clientId": "x"}},
		{"write a platform (admin) app", "POST", "/v1/iam/application", map[string]any{"owner": "admin", "name": "x", "clientId": "x"}},
	}
	for _, c := range deny {
		t.Run("deny/"+c.name, func(t *testing.T) {
			if got := h.do(t, c.method, c.path, boss, c.body); got != http.StatusForbidden {
				t.Fatalf("org admin %s %s (foreign) = %d, want 403", c.method, c.path, got)
			}
		})
	}
}

// 6. A regular user may read its own user record (guard admits it) but not touch
// another's, and may NOT write even its own record — a raw self-write would let
// it carry isAdmin and self-promote, so writes are refused outright.
func TestRegularUserSelfServiceOnly(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	// Reading own record: the guard admits it (not 401/403). The Phase-1 GET
	// handler binds no query, so the status is the handler's, never the guard's
	// forbid — the point here is that the guard did NOT block self-read.
	if got := h.do(t, "GET", "/v1/iam/users/get?owner=hanzo&name=alice", alice, nil); got == http.StatusForbidden || got == http.StatusUnauthorized {
		t.Fatalf("regular self-read = %d, want the guard to admit it (not 401/403)", got)
	}

	// Everything else a regular user might try is refused.
	deny := []struct {
		name, method, path string
		body               any
	}{
		{"read another user", "GET", "/v1/iam/users/get?owner=hanzo&name=boss", nil},
		{"list the org's users", "GET", "/v1/iam/users?owner=hanzo", nil},
		{"update own record (self-promote)", "POST", "/v1/iam/users/update", map[string]any{"user": map[string]any{"owner": "hanzo", "name": "alice", "isAdmin": true}}},
		{"create a user", "POST", "/v1/iam/users", user("hanzo", "puppet")},
		{"delete another user", "POST", "/v1/iam/users/delete", map[string]any{"owner": "hanzo", "name": "boss"}},
		{"read another org", "GET", "/v1/iam/users/get?owner=orgb&name=bob", nil},
	}
	for _, c := range deny {
		t.Run("deny/"+c.name, func(t *testing.T) {
			if got := h.do(t, c.method, c.path, alice, c.body); got != http.StatusForbidden {
				t.Fatalf("regular user %s %s = %d, want 403", c.method, c.path, got)
			}
		})
	}
}

// 7. Public routes are reachable with NO bearer — the pre-auth OIDC/OAuth and
// front-door surface a browser must reach before it holds a token. "Reachable"
// means NOT the guard's 401: the endpoint's own handler answers (which may be a
// 400 for a missing param — that is the handler, past the guard).
func TestPublicRoutesNeedNoBearer(t *testing.T) {
	h := newHarness(t)
	public := []struct{ method, path string }{
		{"GET", "/healthz"},
		{"GET", "/.well-known/openid-configuration"},
		{"GET", "/v1/iam/.well-known/openid-configuration"},
		{"GET", "/v1/iam/.well-known/jwks"},
		{"POST", "/v1/iam/login"},
		{"GET", "/v1/iam/oauth/authorize"},
		{"POST", "/v1/iam/oauth/token"},
		{"GET", "/v1/iam/get-app-login"},
		{"GET", "/v1/iam/auth/methods"},
		{"POST", "/v1/iam/oauth/logout"},
	}
	for _, c := range public {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			if got := h.do(t, c.method, c.path, "", map[string]any{}); got == http.StatusUnauthorized {
				t.Fatalf("public %s %s = 401, want the endpoint reachable without a bearer", c.method, c.path)
			}
		})
	}
	// userinfo is bearer-gated but self-verifying: no bearer → its OWN 401
	// (WWW-Authenticate), which is correct and must not be double-gated away.
	if got := h.do(t, "GET", "/v1/iam/oauth/userinfo", "", nil); got != http.StatusUnauthorized {
		t.Fatalf("userinfo no bearer = %d, want its own 401", got)
	}
}

// 8. Bad bearers are refused with the same opaque 401 (no oracle): expired,
// wrong algorithm (HMAC / none — never in the allowlist), a kid that names no
// trusted cert, and a good-shape token under the wrong key. This reuses the
// Phase-2 verifier defenses verbatim.
func TestBadBearersAre401(t *testing.T) {
	h := newHarness(t)
	other := genRSA(t)
	path, body := "/v1/iam/users", user("hanzo", "x")

	bad := map[string]string{
		"expired":    h.mint(t, "admin/root", time.Now().Add(-time.Hour)),
		"forged kid": mintKid(t, h.key, "cert-nonexistent", "admin/root"),
		"wrong key":  mintKid(t, other, signingKid, "admin/root"),
		"hmac alg":   signHS256(t, signingKid, "admin/root"),
		"alg none":   forgeNone(signingKid, "admin/root"),
		"garbage":    "not.a.jwt",
	}
	for name, tok := range bad {
		t.Run(name, func(t *testing.T) {
			if got := h.do(t, "POST", path, tok, body); got != http.StatusUnauthorized {
				t.Fatalf("bad bearer %q = %d, want 401", name, got)
			}
		})
	}

	// A revoked (forbidden) user's otherwise-valid token is refused too.
	t.Run("revoked user", func(t *testing.T) {
		if got := h.do(t, "POST", path, h.token(t, "hanzo/ghost"), body); got != http.StatusUnauthorized {
			t.Fatalf("revoked user = %d, want 401", got)
		}
	})
}

// Org-confusion escalation defense: a token minted through a SHARED admin-org
// app carries owner/organization = "admin" while its subject is a tenant user.
// The guard authorizes from the subject (the real user's org), never the owner
// claim, so this token is a hanzo REGULAR user — it cannot write an admin cert
// or reach across orgs, exactly as if the misleading claim were absent.
func TestOwnerClaimCannotEscalate(t *testing.T) {
	h := newHarness(t)
	// alice is a regular hanzo user; the token lies that owner == admin.
	tok := h.sharedAppToken(t, "hanzo/alice", "admin")
	cases := []struct {
		name, method, path string
		body               any
	}{
		{"write admin signing cert", "POST", "/v1/iam/certs", cert("admin", "cert-forge")},
		{"overwrite live admin cert", "POST", "/v1/iam/certs/update", cert("admin", signingKid)},
		{"create a user cross-org", "POST", "/v1/iam/users", user("orgb", "mole")},
		{"promote self in own org", "POST", "/v1/iam/users/update", map[string]any{"user": map[string]any{"owner": "hanzo", "name": "alice", "isAdmin": true}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.do(t, c.method, c.path, tok, c.body); got != http.StatusForbidden {
				t.Fatalf("owner-claim=admin %s %s = %d, want 403 (claim must not escalate)", c.method, c.path, got)
			}
		})
	}
}

// A verified token whose subject names NO live user — a machine token, a
// since-deleted user, or a forged-looking "admin/<nobody>" — authenticates but
// carries no authority: SuperAdmin requires a real member of the admin org, so
// the phantom-admin subject is refused everywhere.
func TestPhantomSubjectHasNoAuthority(t *testing.T) {
	h := newHarness(t)
	ghostAdmin := h.token(t, "admin/nobody") // no such user seeded
	ghostTenant := h.token(t, "hanzo/nobody")
	cases := []struct {
		name, tok, method, path string
		body                    any
	}{
		{"phantom admin -> admin cert", ghostAdmin, "POST", "/v1/iam/certs", cert("admin", "cert-forge")},
		{"phantom admin -> user in admin org", ghostAdmin, "POST", "/v1/iam/users", user("admin", "x")},
		{"phantom admin -> user in a tenant", ghostAdmin, "POST", "/v1/iam/users", user("hanzo", "x")},
		{"phantom tenant -> user in own org", ghostTenant, "POST", "/v1/iam/users", user("hanzo", "x")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.do(t, c.method, c.path, c.tok, c.body); got != http.StatusForbidden {
				t.Fatalf("%s = %d, want 403 (phantom subject has no authority)", c.name, got)
			}
		})
	}
}

// The framework's generic side doors (MCP tool-call, OpenAPI doc) are gated by
// the same fail-closed default: the guard runs first as global middleware, so a
// bearer-less hit is 401 (the guard), never 404 or an unauthorized invocation.
func TestFrameworkSideDoorsAreGated(t *testing.T) {
	h := newHarness(t)
	// tools/call that would create an admin cert if MCP were an open door.
	mcp := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "createCert", "arguments": cert("admin", "cert-forge")},
	}
	if got := h.do(t, "POST", "/mcp", "", mcp); got != http.StatusUnauthorized {
		t.Fatalf("POST /mcp no bearer = %d, want 401 (guard fail-closed, not an open door)", got)
	}
	// A non-SuperAdmin bearer cannot drive /mcp either: the tool arguments hide
	// the owner, so the guard sees an empty owner and refuses a non-super.
	boss := h.token(t, "hanzo/boss")
	if got := h.do(t, "POST", "/mcp", boss, mcp); got != http.StatusForbidden {
		t.Fatalf("POST /mcp non-super = %d, want 403", got)
	}
	if got := h.do(t, "GET", "/.well-known/openapi.json", "", nil); got != http.StatusUnauthorized {
		t.Fatalf("GET openapi.json no bearer = %d, want 401", got)
	}
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Connecting a provider to an account you already hold. Unlink existed with no
// counterpart, so the only way a link was ever made was the address coincidence in
// linkOrProvision — and once unlinked, that coincidence was the only way back.

// beginLink drives POST /v1/iam/link and returns the envelope.
func beginLink(t *testing.T, app *zip.App, bearer, provider, clientID, returnUri string) (map[string]any, string) {
	t.Helper()
	req := jsonReq("POST", PathLink, map[string]any{
		"provider": provider, "clientId": clientID, "returnUri": returnUri,
	})
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, body := do(t, app, req)
	return decode(t, body), cookieKV(resp.Header.Get("Set-Cookie"))
}

// linkable declares an OIDC provider on the "conf" app the bearer is minted
// through, so one server can both authenticate the caller and run the IdP leg.
func linkable(t *testing.T, db orm.DB, m *mockOIDC) {
	t.Helper()
	seedOIDCProvider(t, db, "conf", m)
}

// The happy path: a signed-in person names a provider, follows it, and comes back
// with the identity attached to the account they were already holding.
func TestLink_AttachesToTheCallerAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)
	// The IdP's address is NOT alice's — the whole point: the coincidence is absent,
	// and the link happens anyway because she asked for it.
	m.email = "someone-else@gmail.com"

	access := accessTokenFor(t, app, "openid") // bearer for hanzo/alice
	env, cookie := beginLink(t, app, access, fedProvGoogle, "conf", testRedirect)
	if env["status"] != "ok" {
		t.Fatalf("link did not start: %v", env["msg"])
	}
	idpURL, _ := env["data"].(string)
	if !strings.HasPrefix(idpURL, m.URL) {
		t.Fatalf("link must hand back the IdP URL, got %q", idpURL)
	}
	q := mustQuery(t, idpURL)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-link", cookie), testRedirect)
	if got := mustQuery(t, loc).Get("linked"); got != fedProvGoogle {
		t.Fatalf("the return must name what was connected, got %q (%s)", got, loc)
	}
	// A link is not a sign-in: no code was minted for it.
	if mustQuery(t, loc).Get("code") != "" {
		t.Fatalf("a link minted an authorization code: %s", loc)
	}
	if got := userRow(t, db, "alice").Google; got != m.sub {
		t.Fatalf("the provider subject was not attached: %q", got)
	}
	// And no second account was created for the IdP's own address.
	if u, _ := store.GetUserByEmail(tctx(), db, "hanzo", "someone-else@gmail.com"); u != nil {
		t.Fatalf("linking created an account for the provider's address: %s/%s", u.Owner, u.Name)
	}
}

// The account is fixed at BEGIN, from the caller's proven identity — so a body
// naming another account changes nothing. The form has no such field; this asserts
// there is nothing to add one to.
func TestLink_RequiresAuthentication(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkable(t, db, newMockOIDC(t, fedGoogleCID))

	env, _ := beginLink(t, app, "", fedProvGoogle, "conf", testRedirect)
	if env["status"] != "error" {
		t.Fatalf("an unauthenticated link must be refused, got %v", env)
	}
	if userRow(t, db, "alice").Google != "" {
		t.Fatal("an unauthenticated request attached a provider")
	}
}

// A provider identity belongs to ONE account. A second person who signs in at the
// same provider cannot take it: the attach is refused and the first link survives.
func TestLink_SubjectAlreadyOnAnotherAccountRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)

	// Bob already holds this provider identity.
	seedUserInOrg(t, db, "hanzo", "bob", "bob@hanzo.ai", "pw")
	bob := userRow(t, db, "bob")
	bob.Google = m.sub
	if err := bob.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("seed bob's link: %v", err)
	}

	access := accessTokenFor(t, app, "openid") // alice
	env, cookie := beginLink(t, app, access, fedProvGoogle, "conf", testRedirect)
	if env["status"] != "ok" {
		t.Fatalf("link did not start: %v", env["msg"])
	}
	q := mustQuery(t, env["data"].(string))
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-steal", cookie), testRedirect)
	if mustQuery(t, loc).Get("error") != "access_denied" {
		t.Fatalf("taking another account's identity must be refused, got %s", loc)
	}
	if userRow(t, db, "alice").Google != "" {
		t.Fatal("alice took an identity that belonged to bob")
	}
	if got := userRow(t, db, "bob").Google; got != m.sub {
		t.Fatalf("bob's link was disturbed: %q", got)
	}
}

// The return target is validated against the application's registered list, so the
// endpoint cannot be turned into an open redirector by the page that calls it.
func TestLink_UnregisteredReturnUriRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkable(t, db, newMockOIDC(t, fedGoogleCID))

	access := accessTokenFor(t, app, "openid")
	env, _ := beginLink(t, app, access, fedProvGoogle, "conf", "https://attacker.example/collect")
	if env["status"] != "error" {
		t.Fatalf("an unregistered returnUri must be refused, got %v", env)
	}
	// No transaction was minted for it.
	n, err := orm.TypedQuery[schema.FederationState](db).Count(context.Background())
	if err != nil {
		t.Fatalf("count states: %v", err)
	}
	if n != 0 {
		t.Fatalf("a refused link left %d transactions behind", n)
	}
}

// A provider already connected is said so up front, rather than after a round-trip
// to the IdP that could only end the same way.
func TestLink_AlreadyConnectedRefusedBeforeTheRoundTrip(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkable(t, db, newMockOIDC(t, fedGoogleCID))
	u := userRow(t, db, "alice")
	u.Google = "already-here"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	access := accessTokenFor(t, app, "openid")
	env, _ := beginLink(t, app, access, fedProvGoogle, "conf", testRedirect)
	if env["status"] != "error" {
		t.Fatalf("an already-connected provider must be refused, got %v", env)
	}
	if got := userRow(t, db, "alice").Google; got != "already-here" {
		t.Fatalf("the existing link was disturbed: %q", got)
	}
}

// A link transaction is single-use and browser-bound, exactly as a sign-in's is:
// the callback needs the cookie the begin leg set, and a replay attaches nothing.
func TestLink_TransactionIsBoundAndSingleUse(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)

	access := accessTokenFor(t, app, "openid")
	env, cookie := beginLink(t, app, access, fedProvGoogle, "conf", testRedirect)
	q := mustQuery(t, env["data"].(string))
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	state := q.Get("state")

	// Without the browser binding the callback attaches nothing — this is the
	// login-CSRF defense the sign-in flow relies on, and a link needs it more: the
	// prize is somebody else's account.
	resp := callback(t, app, state, "idp-code-1", "")
	if resp.StatusCode == 302 {
		t.Fatalf("a callback with no bind cookie was redirected: %s", resp.Header.Get("Location"))
	}
	if userRow(t, db, "alice").Google != "" {
		t.Fatal("a callback with no bind cookie attached a provider")
	}

	// The real browser completes it once.
	loc := requireRedirect(t, callback(t, app, state, "idp-code-1", cookie), testRedirect)
	if mustQuery(t, loc).Get("linked") == "" {
		t.Fatalf("the link did not complete: %s", loc)
	}
	// A replay finds the transaction spent.
	replay := callback(t, app, state, "idp-code-1", cookie)
	if replay.StatusCode == 302 {
		t.Fatalf("a replayed link was accepted: %s", replay.Header.Get("Location"))
	}
}

// Link and unlink are inverses, and the loop closes: what unlink removes, link puts
// back — which is the whole point, since re-linking used to need an address
// coincidence a person cannot arrange.
func TestLink_ClosesTheLoopWithUnlink(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)
	// The app permits disconnecting, which is the tenant policy unlink honours, and
	// alice signed up through it — the row unlink resolves that policy from.
	permitUnlink(t, db, "conf", fedProvGoogle)
	alice := userRow(t, db, "alice")
	alice.SignupApplication = "conf"
	if err := alice.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("set signup application: %v", err)
	}
	access := accessTokenFor(t, app, "openid")

	// Link.
	env, cookie := beginLink(t, app, access, fedProvGoogle, "conf", testRedirect)
	q := mustQuery(t, env["data"].(string))
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-1", cookie), testRedirect)
	if userRow(t, db, "alice").Google == "" {
		t.Fatal("link did not attach")
	}

	// Unlink. Alice keeps her password, so the last-credential check permits it.
	req := jsonReq("POST", PathUnlink, map[string]any{
		"providerType": "Google",
		"user":         map[string]string{"owner": "hanzo", "name": "alice"},
	})
	req.Header.Set("Authorization", "Bearer "+access)
	_, body := do(t, app, req)
	if m2 := decode(t, body); m2["status"] != "ok" {
		t.Fatalf("unlink failed: %v", m2["msg"])
	}
	if got := userRow(t, db, "alice").Google; got != "" {
		t.Fatalf("unlink left the connector set: %q", got)
	}

	// And link again — the state the coincidence could never reach.
	env, cookie = beginLink(t, app, access, fedProvGoogle, "conf", testRedirect)
	q = mustQuery(t, env["data"].(string))
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-2", cookie), testRedirect)
	if mustQuery(t, loc).Get("linked") != fedProvGoogle {
		t.Fatalf("re-linking did not complete: %s", loc)
	}
	if userRow(t, db, "alice").Google != m.sub {
		t.Fatal("re-linking did not attach")
	}
}

// permitUnlink turns on the application's CanUnlink flag for one provider item —
// the tenant policy unlink consults before letting a holder disconnect.
func permitUnlink(t *testing.T, db orm.DB, appClientID, providerName string) {
	t.Helper()
	a, err := orm.Get[schema.Application](db, "admin/"+appClientID)
	if err != nil {
		t.Fatalf("load app: %v", err)
	}
	for _, it := range a.Providers {
		if it != nil && it.Name == providerName {
			it.CanUnlink = true
		}
	}
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("permit unlink: %v", err)
	}
}

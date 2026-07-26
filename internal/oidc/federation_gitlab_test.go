// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// GitLab is brokered as OIDC, not as a second OAuth2+userinfo dialect. gitlab.com
// publishes a discovery document, so the existing OIDC leg services it — and
// verifies the identity out of a JWKS-checked, nonce-bound id_token, which the
// fork's bespoke connector never did. These tests hold both halves: the row
// classifies and resolves without any per-row configuration, and a real
// round-trip provisions a user through it.

const fedProvGitLab = "provider-gitlab"

// A GitLab row carries no issuerUrl of its own — the type pins the published one,
// exactly as Google does. Both idpKind and oidcResolve read the same table, so
// "classified as OIDC" and "resolves to an issuer" cannot disagree.
func TestFederation_GitLabResolvesThePublishedIssuer(t *testing.T) {
	p := &schema.Provider{Name: fedProvGitLab, Category: "OAuth", Type: "GitLab", ClientId: "gl-id"}

	if got := idpKind(p); got != "oidc" {
		t.Fatalf("idpKind = %q, want oidc", got)
	}
	if got := defaultIssuer(p); got != "https://gitlab.com" {
		t.Errorf("defaultIssuer = %q, want https://gitlab.com", got)
	}
	if err := federable(p); err != nil {
		t.Errorf("a GitLab row must be federable: %v", err)
	}

	// A self-hosted GitLab pins its own issuer, and the row's value wins.
	self := &schema.Provider{Name: "gl-self", Type: "GitLab", ClientId: "x", IssuerUrl: "https://gitlab.example.com"}
	if got := idpKind(self); got != "oidc" {
		t.Errorf("self-hosted idpKind = %q, want oidc", got)
	}
}

// The full round-trip on a GitLab-typed row: authorize → IdP → callback → iam2
// code, provisioning a local user stamped on the gitlab connector column. The
// issuer points at the mock so no live GitLab is contacted; what is under test is
// that the GitLab dialect dispatches into the hardened OIDC leg at all.
func TestFederation_GitLabCallbackProvisionsUser(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, "gitlab-oauth-client")

	p := orm.New[schema.Provider](db)
	p.Owner, p.Name = "admin", fedProvGitLab
	p.Category, p.Type = "OAuth", "GitLab"
	p.ClientId, p.ClientSecret = m.clientID, "gitlab-secret-do-not-log"
	p.IssuerUrl = m.URL
	p.SetId("admin/" + fedProvGitLab)
	if err := p.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed gitlab provider: %v", err)
	}
	linkProvider(t, db, "webapp", fedProvGitLab)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGitLab)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	// The OIDC leg is what ran: it sent a nonce and an S256 challenge, which the
	// GitHub dialect does not.
	if q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("GitLab did not take the OIDC leg: nonce=%q method=%q", q.Get("nonce"), q.Get("code_challenge_method"))
	}

	resp := callback(t, app, q.Get("state"), "idp-code-gl", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	cb, _ := url.Parse(loc)
	if cb.Query().Get("code") == "" {
		t.Fatalf("callback must redirect with an iam2 code; got %q", loc)
	}

	u, err := store.GetUserByConnector(context.Background(), db, "hanzo", "gitlab", m.sub)
	if err != nil || u == nil {
		t.Fatalf("provisioned user not found on the gitlab connector: %v", err)
	}
	if u.PasswordHash != "" || u.IsAdmin {
		t.Error("a federated user gets no password and never isAdmin")
	}
	if !u.EmailVerified || u.Email != m.email {
		t.Errorf("verified email not carried: verified=%v email=%q", u.EmailVerified, u.Email)
	}
}

// The servicing side of the advertising invariant: a provider the broker cannot
// federate is refused at the begin leg with the reason, and never reaches an IdP.
// authMethods withholds the same rows, so a user never gets here by clicking.
func TestFederation_UnfederableProviderRefusedAtBeginLeg(t *testing.T) {
	for name, p := range map[string]*schema.Provider{
		"unsupported dialect": {Name: "provider-apple", Category: "OAuth", Type: "Apple", ClientId: "apple-id", ClientSecret: "s"},
		"no identity binding": {Name: "provider-custom", Category: "OAuth", Type: "Custom", ClientId: "c-id", ClientSecret: "s", IssuerUrl: "https://idp.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})

			row := orm.New[schema.Provider](db)
			model := row.Model
			*row = *p
			row.Model = model
			row.Owner = "admin"
			row.SetId("admin/" + p.Name)
			if err := row.CreateCtx(context.Background()); err != nil {
				t.Fatalf("seed provider: %v", err)
			}
			linkProvider(t, db, "webapp", p.Name)

			if err := federable(row); err == nil {
				t.Fatal("this provider must not be federable")
			}

			q := url.Values{
				"response_type":         {"code"},
				"client_id":             {"webapp"},
				"redirect_uri":          {testRedirect},
				"scope":                 {"openid email profile"},
				"state":                 {fedAppState},
				"code_challenge":        {ComputeS256Challenge(fedVerifier)},
				"code_challenge_method": {"S256"},
				"provider":              {p.Name},
			}
			resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+q.Encode()))
			loc := resp.Header.Get("Location")
			if loc == "" {
				t.Fatalf("expected an error redirect, got status %d", resp.StatusCode)
			}
			// Back to the application with an error — never onward to an IdP.
			if u, _ := url.Parse(loc); u.Query().Get("error") != "invalid_request" {
				t.Fatalf("want an invalid_request error redirect to the app, got %q", loc)
			}
		})
	}
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// D6: the platform's own applications that share one sign-out (IAM_SIGNOUT_APPS)
// are answered silently on a sign-in origin, because their sign-out ends that
// origin's session too. prompt=none on hanzo.ai then mints a code from the
// session there. Everything else about the refusal holds: a request with no
// prompt still gets the hosted "continue as" page, an application off the list
// is still login_required, and so is a tenant's application whose clientId
// spells a listed one, since only a reserved signing owner's applications count.
func TestAuthorize_FirstPartySilentAtSigninOrigin(t *testing.T) {
	t.Setenv(envSignoutApps, "second,lookalike")
	app, db := newServer(t)
	twoApps(t, db)
	seedApp(t, db, appOpts{clientID: "unlisted", redirectURIs: []string{secondRedirect}})
	seedTenantApp(t, db, "acme", "lookalike", secondRedirect)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	cookie := signIn(t, app, "portal")

	ask := func(q url.Values) *http.Response {
		req := formReqNoBody("GET", authorizeURL(q))
		req.Host = "hanzo.ai"
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Dest", "document")
		resp, _ := do(t, app, req)
		return resp
	}
	silent := func(client string) url.Values {
		q := silentQuery("verifier-silent-at-signin-origin-0123456789012345678")
		q.Set("client_id", client)
		q.Set("prompt", "none")
		return q
	}

	// A listed first-party app: answered from the session on hanzo.ai.
	if loc := requireRedirect(t, ask(silent("second")), secondRedirect); !strings.Contains(loc, "code=") || strings.Contains(loc, "error=") {
		t.Fatalf("prompt=none for a listed app on hanzo.ai = %q, want a code", loc)
	}

	// The same app with no prompt still asks first: the hosted page, no code.
	q := silent("second")
	q.Del("prompt")
	resp := ask(q)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, hostedLoginPath+"?") || strings.Contains(loc, "code=") {
		t.Fatalf("no prompt for a listed app on hanzo.ai answered %d to %q, want the hosted page", resp.StatusCode, loc)
	}

	// Off the list, and a tenant's lookalike on it: both still refused.
	for _, client := range []string{"unlisted", "lookalike"} {
		loc := requireRedirect(t, ask(silent(client)), secondRedirect)
		if !strings.Contains(loc, "error=login_required") || strings.Contains(loc, "code=") {
			t.Fatalf("prompt=none for %s on hanzo.ai = %q, want error=login_required and no code", client, loc)
		}
	}
}

// With the list unset nothing is answered silently on a sign-in origin: the
// refusal fails closed.
func TestAuthorize_SilentAtSigninOriginFailsClosed(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	cookie := signIn(t, app, "portal")

	q := silentQuery("verifier-silent-fails-closed-01234567890123456789012")
	q.Set("prompt", "none")
	req := formReqNoBody("GET", authorizeURL(q))
	req.Host = "hanzo.ai"
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp, _ := do(t, app, req)
	if loc := requireRedirect(t, resp, secondRedirect); !strings.Contains(loc, "error=login_required") {
		t.Fatalf("with IAM_SIGNOUT_APPS unset, prompt=none on hanzo.ai = %q, want login_required", loc)
	}
}

// seedTenantApp creates a public client owned by a tenant org rather than the
// platform: what a customer registers through the console.
func seedTenantApp(t *testing.T, db orm.DB, owner, clientID, redirect string) {
	t.Helper()
	seedRSACert(t, db, "cert-"+clientID)
	a := orm.New[schema.Application](db)
	a.Owner = owner
	a.Name = clientID
	a.ClientId = clientID
	a.Organization = owner
	a.Cert = "cert-" + clientID
	a.EnablePassword = true
	a.ExpireInHours = 1
	a.RedirectUris = []string{redirect}
	a.SetId(owner + "/" + clientID)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed tenant app: %v", err)
	}
}

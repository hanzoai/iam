// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/keys"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
)

// An app configured by its publishable key alone learns the client id and org it
// signs in as, and signs a person in as a public PKCE client with no secret.
func TestPublishableKeySignsInAsTheAppItNames(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedOrg(t, db, "acme")
	seedUserInOrg(t, db, "acme", "ann", "ann@acme.example", "pw-ann")
	pk, err := keys.Preset(tctx(), db, "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if again, err := keys.Preset(tctx(), db, "acme", "Acme"); err != nil || again != pk {
		t.Fatalf("a second preset = %q (err=%v), want the same %q", again, err, pk)
	}

	_, body := do(t, app, formReqNoBody("GET", PathAuthApplication+"?publishableKey="+pk))
	view, _ := decode(t, body)["data"].(map[string]any)
	if view["clientId"] != "acme-app" || view["organization"] != "acme" || view["clientSecret"] != "" {
		t.Fatalf("the pk resolved to %v, want acme-app of acme with no secret", view)
	}

	verifier := "verifier-publishable-key-0123456789012345678901234567"
	redirect := "http://127.0.0.1:5173/auth/callback"
	q := url.Values{
		"clientId": {"acme-app"}, "redirectUri": {redirect}, "scope": {"openid"},
		"code_challenge": {pkce.Challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	_, body = do(t, app, jsonReq("POST", PathLogin+"?"+q.Encode(), map[string]any{
		"type": "code", "clientId": "acme-app", "organization": "acme", "username": "ann", "password": "pw-ann",
	}))
	code, _ := decode(t, body)["data"].(string)
	if code == "" {
		t.Fatalf("sign-in: %s", body)
	}
	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"acme-app"}, "redirect_uri": {redirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("exchange: %d %v", resp.StatusCode, tok)
	}
}

// A publishable key resolves only to the application it names in its own org:
// not a secret key, not a key that names no application, not one naming another
// org's application, and not both selectors at once.
func TestPublishableKeyNamesItsOwnOrgsAppOnly(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedOrg(t, db, "acme")
	pk, err := keys.Preset(tctx(), db, "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]*schema.Key{
		"secret":    {Owner: "acme", Name: "s", AccessKey: "pk-live-secretscope", Application: "acme-app"},
		"unnamed":   {Owner: "acme", Name: "u", AccessKey: "pk-live-unnamed", Scope: schema.KeyScopePublish},
		"elsewhere": {Owner: "evil", Name: "e", AccessKey: "pk-live-elsewhere", Scope: schema.KeyScopePublish, Application: "acme-app"},
	} {
		row := orm.New[schema.Key](db)
		model := row.Model
		*row = *k
		row.Model = model
		row.State = "Active"
		row.SetId(k.Owner + "/" + k.Name)
		if err := row.CreateCtx(tctx()); err != nil {
			t.Fatal(err)
		}
		_, body := do(t, app, formReqNoBody("GET", PathAuthApplication+"?publishableKey="+k.AccessKey))
		if m := decode(t, body); m["status"] != "error" {
			t.Errorf("%s key resolved: %s", name, body)
		}
	}
	_, body := do(t, app, formReqNoBody("GET", PathAuthApplication+"?publishableKey="+pk+"&clientId=conf"))
	if m := decode(t, body); m["status"] != "error" {
		t.Errorf("both selectors answered: %s", body)
	}
}

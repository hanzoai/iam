// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
)

// GET /v1/iam/auth/methods is what a login page renders itself from, so its one
// invariant is that every method it reports is a method that COMPLETES. These
// tests hold that line from the offering side; federation_test.go holds the
// servicing side. A method may only appear here if the subsystem that owns it
// says it can service the request — never merely because a row enables it.

// authMethods drives the endpoint and returns the decoded data object.
func authMethodsFor(t *testing.T, app *zip.App, clientID string) map[string]any {
	t.Helper()
	_, raw := do(t, app, formReqNoBody("GET", PathAuthMethods+"?clientId="+clientID))
	env := decode(t, raw)
	if env["status"] != "ok" {
		t.Fatalf("auth/methods: %v", env)
	}
	data, _ := env["data"].(map[string]any)
	if data == nil {
		t.Fatalf("auth/methods returned no data: %v", env)
	}
	return data
}

// oauthNames lists the provider names auth/methods offers as OAuth buttons.
func oauthNames(t *testing.T, data map[string]any) []string {
	t.Helper()
	var names []string
	list, _ := data["oauth"].([]any)
	for _, it := range list {
		m, _ := it.(map[string]any)
		n, _ := m["name"].(string)
		names = append(names, n)
	}
	return names
}

// seedProvider creates a provider row and links it (sign-in enabled) onto an app.
func seedProvider(t *testing.T, db orm.DB, appClientID string, p *schema.Provider) {
	t.Helper()
	row := orm.New[schema.Provider](db)
	model := row.Model
	*row = *p
	row.Model = model
	row.Owner = "admin"
	row.SetId("admin/" + p.Name)
	if err := row.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed provider %s: %v", p.Name, err)
	}
	linkProvider(t, db, appClientID, p.Name)
}

// enableCodeSignin flips the application's EnableCodeSignin, the row-level wish
// the endpoint must AND with the service's actual ability to deliver.
func enableCodeSignin(t *testing.T, db orm.DB, appClientID string) {
	t.Helper()
	a, err := orm.Get[schema.Application](db, "admin/"+appClientID)
	if err != nil {
		t.Fatalf("load app: %v", err)
	}
	a.EnableCodeSignin = true
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("enable code signin: %v", err)
	}
}

// The defect: an application that ENABLES code sign-in still must not have the
// method advertised while no transport can carry the code. The wish is the app's;
// the ability is the service's, and the answer is the conjunction.
func TestAuthMethods_CodeWithheldWhileDeliveryIsUnwired(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp"})
	enableCodeSignin(t, db, "webapp")

	// No NOTIFY_ENDPOINT is reachable in this test, so the rail is down and the
	// method must be withheld even though the application asks for it.
	if code := authMethodsFor(t, app, "webapp")["code"]; code != false {
		t.Fatalf("code = %v, want false: the app enables it but the rail is unreachable", code)
	}
}

// The advertised set and the servable set are ONE set. A provider whose dialect
// the broker cannot speak is withheld no matter how completely its row is filled
// in — otherwise the button reaches idpAuthorizeURL and dies there.
func TestAuthMethods_OffersOnlyFederableProviders(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp"})

	// Servable: the two dialects the broker implements, plus GitLab, which is an
	// OIDC issuer and needs no issuerUrl of its own.
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-github", Category: "OAuth", Type: "GitHub", ClientId: "gh-id", ClientSecret: "gh-secret",
	})
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-google", Category: "OAuth", Type: "Google", ClientId: "goog-id", ClientSecret: "goog-secret",
	})
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-gitlab", Category: "OAuth", Type: "GitLab", ClientId: "gl-id", ClientSecret: "gl-secret",
	})
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-okta", Category: "OAuth", Type: "Okta", ClientId: "okta-id",
		ClientSecret: "okta-secret", IssuerUrl: "https://example.okta.com",
	})
	// Not servable, first half: real credentials, a dialect the broker does not
	// implement. This is the shape the fork carried some thirty of.
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-apple", Category: "OAuth", Type: "Apple", ClientId: "apple-id", ClientSecret: "apple-secret",
	})
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-facebook", Category: "OAuth", Type: "Facebook", ClientId: "fb-id", ClientSecret: "fb-secret",
	})
	// Not servable, second half: a perfectly good OIDC issuer with NO local
	// column to stamp the returned subject on. A dialect check alone would offer
	// this and it would die at "provider has no local identity binding".
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-custom", Category: "OAuth", Type: "Custom", ClientId: "custom-id",
		ClientSecret: "custom-secret", IssuerUrl: "https://idp.example.com",
	})
	// A Web3 connector miscategorised as OAuth — the exact row shape the live
	// store carries. It is native challenge/response, not federation, so as an
	// OAuth button it would dead-end.
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-web3", Category: "OAuth", Type: "Web3Onboard", ClientId: "w3-id",
	})

	offered := map[string]bool{}
	for _, n := range oauthNames(t, authMethodsFor(t, app, "webapp")) {
		offered[n] = true
	}
	for _, want := range []string{"provider-github", "provider-google", "provider-gitlab", "provider-okta"} {
		if !offered[want] {
			t.Errorf("%s is federable and must be offered", want)
		}
	}
	for _, never := range []string{"provider-apple", "provider-facebook", "provider-web3", "provider-custom"} {
		if offered[never] {
			t.Errorf("%s is not federable and must never be offered — clicking it dead-ends", never)
		}
	}
}

// The invariant as a property rather than a case list: whatever is offered, the
// broker must be able to federate it. Stated this way, a provider type added to
// the connector registry or the issuer table without being brokered end to end
// cannot slip into the login page unnoticed.
func TestAuthMethods_EveryOfferedProviderIsFederable(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp"})
	for _, p := range []*schema.Provider{
		{Name: "p-github", Category: "OAuth", Type: "GitHub", ClientId: "a"},
		{Name: "p-google", Category: "OAuth", Type: "Google", ClientId: "b"},
		{Name: "p-gitlab", Category: "OAuth", Type: "GitLab", ClientId: "c"},
		{Name: "p-apple", Category: "OAuth", Type: "Apple", ClientId: "d"},
		{Name: "p-wechat", Category: "OAuth", Type: "WeChat", ClientId: "e"},
		{Name: "p-linkedin", Category: "OAuth", Type: "LinkedIn", ClientId: "f"},
		{Name: "p-dingtalk", Category: "OAuth", Type: "DingTalk", ClientId: "g"},
		{Name: "p-slack", Category: "OAuth", Type: "Slack", ClientId: "h"},
		{Name: "p-custom", Category: "OAuth", Type: "Custom", ClientId: "i", IssuerUrl: "https://idp.example.com"},
	} {
		seedProvider(t, db, "webapp", p)
	}

	offered := oauthNames(t, authMethodsFor(t, app, "webapp"))
	if len(offered) == 0 {
		t.Fatal("no provider offered — the property would hold vacuously")
	}
	for _, name := range offered {
		row, err := orm.Get[schema.Provider](db, "admin/"+name)
		if err != nil {
			t.Fatalf("offered provider %s has no row: %v", name, err)
		}
		if err := federable(row); err != nil {
			t.Errorf("offered %s, but the broker refuses it: %v", name, err)
		}
	}
}

// An unconfigured provider stays hidden — the pre-existing credential gate is
// orthogonal to the dialect gate and both must hold.
func TestAuthMethods_UnconfiguredProviderStaysHidden(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp"})
	seedProvider(t, db, "webapp", &schema.Provider{
		Name: "provider-google", Category: "OAuth", Type: "Google", ClientId: "your-client-id-placeholder",
	})

	if names := oauthNames(t, authMethodsFor(t, app, "webapp")); len(names) != 0 {
		t.Errorf("oauth = %v, want none: the clientId is a placeholder", names)
	}
}

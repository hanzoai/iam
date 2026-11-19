// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
)

// AN APPLICATION THAT CANNOT SIGN SAYS WHICH CERT IT NAMES AND WHY IT CANNOT.
//
// The shape from hanzo-inc/cloud#757: an organization adds a certificate, points
// its application at it, signs a person in — and the exchange answered "this
// application has no signing cert". The row plainly names one. It cannot sign
// because only a cert under a reserved platform owner does (store.GetSigningCert:
// a tenant's cert would otherwise shadow a platform kid), and the answer has to
// say that, or the operator keeps adding certificates that are never read.

// seedTenantCert files a cert under an organization's own name, with key material
// mounted for it — the most a tenant can do, and still not a signing cert.
func seedTenantCert(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = owner, name, "RS256"
	keyring.Set(name, rsaKeyToPEM(t, sharedKey(t)))
	t.Cleanup(func() { keyring.Forget(name) })
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed tenant cert: %v", err)
	}
}

// repoint sets the cert an application names.
func repoint(t *testing.T, a *schema.Application, cert string) {
	t.Helper()
	a.Cert = cert
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("repoint %s at %q: %v", a.Name, cert, err)
	}
}

// The reported flow, end to end: a person signs in, the code is minted, and the
// exchange names the application, the cert it names, and the fix.
func TestToken_aTenantCertIsNamedInTheRefusal(t *testing.T) {
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "portal", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	seedTenantCert(t, db, "hanzo", "portal-own-cert")
	repoint(t, a, "portal-own-cert")

	code, resp, body := loginForCode(t, app, loginParams("portal", "openid profile email"))
	if code == "" {
		t.Fatalf("login did not mint a code: status=%d body=%s", resp.StatusCode, body)
	}
	tokResp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"portal"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	requireError(t, tokResp, tok, 500, "server_error")
	desc, _ := tok["error_description"].(string)
	for _, want := range []string{
		"admin/portal",           // which registration
		"'portal-own-cert'",      // the cert it names
		"platform's signing",     // why that cert cannot sign
		"platform administrator", // who can fix it
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("error_description %q does not say %q", desc, want)
		}
	}
	if _, ok := tok["access_token"]; ok {
		t.Fatal("a token was issued under a tenant's cert")
	}
}

// Every way an application can name nothing it may sign with gets its own words,
// on every grant that mints (client_credentials here: the machine path).
func TestToken_unsignableReasons(t *testing.T) {
	for name, tc := range map[string]struct {
		cert string
		seed func(*testing.T, orm.DB)
		want string
	}{
		"names none": {
			cert: "", want: "names no signing cert",
		},
		"names a tenant's cert": {
			cert: "own-cert",
			seed: func(t *testing.T, db orm.DB) { seedTenantCert(t, db, "hanzo", "own-cert") },
			want: "names the signing cert 'own-cert', which is not one of the platform's signing certs",
		},
		"names a cert that does not exist": {
			cert: "cert-nowhere", want: "names the signing cert 'cert-nowhere', which is not one of the platform's signing certs",
		},
		"names the delegation key": {
			cert: "cert-deleg",
			seed: func(t *testing.T, db orm.DB) {
				seedRSACert(t, db, "cert-deleg")
				c, err := orm.Get[schema.Cert](db, "admin/cert-deleg")
				if err != nil {
					t.Fatal(err)
				}
				c.Scope = schema.CertDelegation
				if err := c.UpdateCtx(context.Background()); err != nil {
					t.Fatal(err)
				}
			},
			want: "names the delegation key 'cert-deleg', which never signs an application's tokens",
		},
	} {
		t.Run(name, func(t *testing.T) {
			app, db := newServer(t)
			a := seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", grants: []string{"client_credentials"}})
			if tc.seed != nil {
				tc.seed(t, db)
			}
			repoint(t, a, tc.cert)

			resp, tok := postToken(t, app, url.Values{
				"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"},
			})
			requireError(t, resp, tok, 500, "server_error")
			desc, _ := tok["error_description"].(string)
			if !strings.Contains(desc, "application 'admin/svc' "+tc.want) {
				t.Fatalf("error_description = %q, want it to say %q", desc, tc.want)
			}
		})
	}
}

// The named error is still ErrNoSigningCert to every caller that asks.
func TestSignerFor_unsignableIsErrNoSigningCert(t *testing.T) {
	_, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret"})
	repoint(t, a, "cert-nowhere")
	_, err := signerFor(context.Background(), db, a, "https://hanzo.id")
	if !errors.Is(err, ErrNoSigningCert) {
		t.Fatalf("signerFor = %v, want ErrNoSigningCert", err)
	}
}

// A stored name is a tenant's input; what reaches error_description stays inside
// the RFC 6749 §5.2 character set and is bounded.
func TestDescSafe(t *testing.T) {
	got := descSafe("a\"b\\c'd\neé" + strings.Repeat("x", 300))
	if !strings.HasPrefix(got, "'a?b?c?d?e?") || !strings.HasSuffix(got, "...'") || len(got) > 140 {
		t.Fatalf("descSafe = %q", got)
	}
	for _, r := range got {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			t.Fatalf("descSafe let %q through: %q", r, got)
		}
	}
}

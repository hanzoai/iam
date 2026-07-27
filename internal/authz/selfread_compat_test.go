// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package authz_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// THE REQUEST CLOUD ACTUALLY MAKES.
//
// The first cut of the self-read grant was unit-tested against authorize() with
// entity "applications" and passed — while production still 403'd, because the
// live caller uses the Casdoor alias /v1/iam/get-application and entityOf resolved
// that to the literal "get-application", which matched no clause. A test written
// against the noun surface proves nothing about the verb surface, exactly like the
// login tests that post authorize params in the body no real client uses.
//
// So every case here goes through the REAL router, over the compat verb, with
// client_secret_basic — the shape hanzo-cloud sends.

// seedAppRow registers an application the way the platform does: owned by admin,
// holding a secret, referencing a signing cert.
func seedAppRow(t *testing.T, db orm.DB, owner, name, secret, cert string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name = owner, name
	a.ClientId, a.ClientSecret = name, secret
	a.Organization, a.Cert = "hanzo", cert
	a.SetId(owner + "/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app %s/%s: %v", owner, name, err)
	}
}

// basicGet issues a GET with client_secret_basic, as a confidential client does.
func (h *harness) basicGet(t *testing.T, path, clientID, secret string) int {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	resp, err := h.app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A relying party bootstraps: read its own application, then the cert that
// application names. Both must succeed over the COMPAT VERB, or cloud panics one
// line after the read it was granted.
func TestSelfRead_OverTheCompatVerbCloudActuallyCalls(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)

	for _, tc := range []struct {
		name, path string
		want       int
	}{
		// The exact request, both spellings of the id the caller may send.
		{"own application, owner-qualified", "/v1/iam/get-application?id=admin%2Fhanzo-cloud", 200},
		{"own cert, owner-qualified", "/v1/iam/get-cert?id=admin%2F" + signingKid, 200},
		{"own cert, bare name", "/v1/iam/get-cert?id=" + signingKid, 200},
		// The native noun surface must agree — one policy, two spellings.
		{"own application, noun surface", "/v1/iam/applications?owner=admin&name=hanzo-cloud", 400}, // reaches the handler = authorized; 400 is the typed read wanting a different shape
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.basicGet(t, tc.path, "hanzo-cloud", "s3cret"); got != tc.want {
				t.Errorf("GET %s as hanzo-cloud = %d, want %d", tc.path, got, tc.want)
			}
		})
	}
}

// The grant stays a SELF-read. Everything an app is not is still refused, over the
// same verb surface that now resolves correctly — normalizing entityOf must not
// have turned the compat aliases into an open door.
func TestSelfRead_StillRefusesEverythingElse(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)
	seedAppRow(t, h.db, "admin", "hanzo-console", "other", signingKid)
	seedAppRow(t, h.db, "hanzo", "hanzo-cloud-tenant", "tsecret", "cert-other")

	// A second signing cert this app does NOT reference.
	c := orm.New[schema.Cert](h.db)
	c.Owner, c.Name = "admin", "cert-lux"
	c.CryptoAlgorithm = "RS256"
	c.SetId("admin/cert-lux")
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	for _, tc := range []struct{ name, path string }{
		{"a sibling application", "/v1/iam/get-application?id=admin%2Fhanzo-console"},
		{"same name, tenant owner", "/v1/iam/get-application?id=hanzo%2Fhanzo-cloud"},
		{"a cert it does not reference", "/v1/iam/get-cert?id=admin%2Fcert-lux"},
		{"a cert it does not reference, bare", "/v1/iam/get-cert?id=cert-lux"},
		{"the whole application list", "/v1/iam/get-applications?owner=admin"},
		{"the whole cert list", "/v1/iam/get-certs?owner=admin"},
		{"a user row", "/v1/iam/get-users?owner=admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.basicGet(t, tc.path, "hanzo-cloud", "s3cret"); got == 200 {
				t.Errorf("GET %s as hanzo-cloud was ADMITTED (200); self-read must not widen", tc.path)
			}
		})
	}
}

// A bad client secret is still not a principal at all.
func TestSelfRead_WrongSecretIsNotAPrincipal(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)
	if got := h.basicGet(t, "/v1/iam/get-application?id=admin%2Fhanzo-cloud", "hanzo-cloud", "wrong"); got == 200 {
		t.Errorf("a wrong client secret read the application row")
	}
}

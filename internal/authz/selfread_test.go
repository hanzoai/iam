// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"

	"github.com/hanzoai/iam/internal/testhttp"
)

// THE REQUEST CLOUD ACTUALLY MAKES.
//
// The first cut of the self-read grant was unit-tested against authorize() and
// passed while production still 403'd, because the entity the path resolved to
// was not the one the clause was written in. A test that calls a function proves
// nothing about the address, exactly like the login tests that post authorize
// params in a body no real client sends.
//
// So every case here goes through the REAL router with client_secret_basic — the
// shape hanzo-cloud sends.

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

// seedCertRow adds a signing cert row under an owner.
func seedCertRow(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	c.CryptoAlgorithm = "RS256"
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert %s/%s: %v", owner, name, err)
	}
}

// basicGet issues a GET with client_secret_basic, as a confidential client does.
func (h *harness) basicGet(t *testing.T, path, clientID, secret string) int {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A relying party bootstraps: read its own application, then the cert that
// application names. Both must succeed, or cloud panics one line after the read
// it was granted.
func TestSelfRead_IsTheReadCloudActuallyMakes(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)
	// Production carries the SAME cert under two owners (seed drift, same keypair);
	// mirror that so the org-qualified spelling the binary sends is exercised.
	seedCertRow(t, h.db, "hanzo", signingKid)

	for _, tc := range []struct {
		name, path string
		want       int
	}{
		// ONE application, by its natural key.
		{"own application", "/v1/iam/applications/admin/hanzo-cloud", 200},
		// 200 is not enough: an earlier shape rewrote the owner to the app's SERVED
		// org, so the read was authorized and then answered "the entity does not
		// exist" — a 200 that is functionally the 403 it replaced. The body is
		// asserted below.
		{"the cert it names", "/v1/iam/certs/admin/" + signingKid, 200},
		// THE ROW THE BINARY REACHES FOR. ai/internal/iam/cert.go:35 addresses the
		// cert under the app's own org, and production carries the same keypair
		// under both owners, so this spelling is the one that matters live.
		{"the cert it names, under its own org", "/v1/iam/certs/hanzo/" + signingKid, 200},
		// The COLLECTION is not the self-read: it asks to enumerate every
		// application under the reserved admin org, which a tenant app may not do.
		// 403 is the right answer and the policy agreeing with itself.
		{"the collection under a reserved org is refused", "/v1/iam/applications?owner=admin", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.basicGet(t, tc.path, "hanzo-cloud", "s3cret"); got != tc.want {
				t.Errorf("GET %s as hanzo-cloud = %d, want %d", tc.path, got, tc.want)
			}
		})
	}
}

// The grant stays a SELF-read. Everything an app is not is still refused.
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
		{"a sibling application", "/v1/iam/applications/admin/hanzo-console"},
		{"same name, tenant owner", "/v1/iam/applications/hanzo/hanzo-cloud"},
		{"a cert it does not reference", "/v1/iam/certs/admin/cert-lux"},
		{"the whole application list", "/v1/iam/applications?owner=admin"},
		{"the whole cert list", "/v1/iam/certs?owner=admin"},
		{"the whole user list", "/v1/iam/users?owner=admin"},
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
	if got := h.basicGet(t, "/v1/iam/applications/admin/hanzo-cloud", "hanzo-cloud", "wrong"); got == 200 {
		t.Errorf("a wrong client secret read the application row")
	}
}

// A 200 whose body says "the entity does not exist" is not a fix. Assert the row
// actually comes back — this is the failure the first probe caught.
func TestSelfRead_ReturnsTheRowNotAnEmptyOk(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)

	req := httptest.NewRequest("GET", "/v1/iam/applications/admin/hanzo-cloud", nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("hanzo-cloud:s3cret")))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var app struct {
		Name  string `json:"name"`
		Owner string `json:"owner"`
		Cert  string `json:"cert"`
	}
	if err := json.Unmarshal(body, &app); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if app.Owner != "admin" || app.Name != "hanzo-cloud" {
		t.Fatalf("got %s/%s, want admin/hanzo-cloud — authorized but unable to read itself: %s",
			app.Owner, app.Name, body)
	}
	if app.Cert != signingKid {
		t.Errorf("cert = %q, want %q — cloud reads this next", app.Cert, signingKid)
	}
}

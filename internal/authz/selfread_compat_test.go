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
// The first cut of the self-read grant was unit-tested against authorize() with
// entity "applications" and passed — while production still 403'd, because the
// live caller uses the the legacy surface alias /v1/iam/applications/get and entityOf resolved
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
//
// THE REQUEST THE CALLER ACTUALLY MAKES. hanzoai/ai builds both as a GET naming
// the partition through one constant (internal/iam/{application,cert}.go,
// PlatformOwner = "admin"), and the METHOD is load-bearing rather than
// incidental: IAM decides read-from-write by it, so the same call shaped as a
// POST is weighed as a write and the self-read grant does not fire — a 403 that
// reads like a permissions regression when the only thing wrong is the verb.
func TestSelfRead_AsTheRelyingPartySendsIt(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)
	// Production carries the SAME cert under two owners (seed drift, same keypair);
	// mirror that so a read naming either partition is exercised.
	seedCertRow(t, h.db, "hanzo", signingKid)

	for _, tc := range []struct {
		name, path string
		want       int
	}{
		// The two reads the bootstrap makes, both owner-qualified, both GET.
		{"own application", "/v1/iam/applications/get?owner=admin&name=hanzo-cloud", 200},
		{"the cert that application names", "/v1/iam/certs/get?owner=admin&name=" + signingKid, 200},
		// The LIST is not the self-read: it asks to enumerate EVERY application
		// under the reserved admin org, which a tenant app may not do. 403 is the
		// policy agreeing with itself rather than a second rule.
		{"the LIST of a reserved org is still refused",
			"/v1/iam/applications?owner=admin&name=hanzo-cloud", 403},
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
		{"a sibling application", "/v1/iam/applications/get?id=admin%2Fhanzo-console"},
		{"same name, tenant owner", "/v1/iam/applications/get?id=hanzo%2Fhanzo-cloud"},
		{"a cert it does not reference", "/v1/iam/certs/get?id=admin%2Fcert-lux"},
		{"a cert it does not reference, bare", "/v1/iam/certs/get?id=cert-lux"},
		{"the whole application list", "/v1/iam/applications?owner=admin"},
		{"the whole cert list", "/v1/iam/certs?owner=admin"},
		{"a user row", "/v1/iam/users?owner=admin"},
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
	if got := h.basicGet(t, "/v1/iam/applications/get?owner=admin&name=hanzo-cloud", "hanzo-cloud", "wrong"); got == 200 {
		t.Errorf("a wrong client secret read the application row")
	}
}

// A 200 whose body says "the entity does not exist" is not a fix. Assert the row
// actually comes back — this is the failure the first probe caught.
func TestSelfRead_ReturnsTheRowNotAnEmptyOk(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)

	req := httptest.NewRequest("GET", "/v1/iam/applications/get?owner=admin&name=hanzo-cloud", nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("hanzo-cloud:s3cret")))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// The read answers the Application itself; the retired surface wrapped every
	// answer in {status, msg, data}, so a decoder still shaped for that finds a
	// zero value and reads exactly like a successful read of an empty record.
	var env struct {
		Name  string `json:"name"`
		Owner string `json:"owner"`
		Cert  string `json:"cert"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if env.Owner != "admin" || env.Name != "hanzo-cloud" {
		t.Errorf("got %s/%s, want admin/hanzo-cloud", env.Owner, env.Name)
	}
	if env.Cert != signingKid {
		t.Errorf("cert = %q, want %q — cloud reads this next", env.Cert, signingKid)
	}
}

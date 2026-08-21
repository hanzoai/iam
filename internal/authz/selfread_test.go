// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"

	"github.com/hanzoai/iam/internal/testhttp"
)

// THE REQUEST A RELYING PARTY ACTUALLY MAKES.
//
// The first cut of the self-read grant was unit-tested against authorize() with
// entity "applications" and passed while production still 403'd, because the
// caller of the day used a second spelling of the same read and entityOf
// resolved it to a literal that matched no clause. That second spelling is gone
// — one address per kind now — so the hazard it created is gone with it. What
// survives is the property it was written to prove, and these cases keep proving
// it: an application may read ITSELF and the cert it names, and nothing else.
//
// Every case goes through the REAL router with client_secret_basic, which is the
// shape a confidential client sends.

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
	return h.basic(t, "GET", path, "", clientID, secret)
}

// basic issues a request with client_secret_basic. The method is a parameter
// because IAM is not uniform about it: a single-entity read is a GET on
// applications and organizations and a POST on certs, and a POST carries its
// target in the BODY rather than the query.
func (h *harness) basic(t *testing.T, method, path, body, clientID, secret string) int {
	t.Helper()
	var payload io.Reader
	if body != "" {
		payload = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, payload)
	req.Host = "hanzo.id"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A relying party bootstraps: read its own application, then the cert that
// application names. Both must succeed, or the caller fails one line after the
// read it was granted.
func TestSelfRead_AnApplicationReadsItselfAndItsCert(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)
	// Production carries the SAME cert under two owners (seed drift, one keypair),
	// so a caller reaches it under either. Mirror that and exercise both.
	seedCertRow(t, h.db, "hanzo", signingKid)

	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"its own application", "GET", "/v1/iam/applications/get?owner=admin&name=hanzo-cloud", "", 200},
		// 200 is not enough on its own: Scope used to rewrite the owner to the
		// app's SERVED org, so a read was authorized and then answered "no such
		// entity" — a 200 that is the 403 it replaced. The body is asserted below.
		{"the cert it names, under admin", "GET",
			"/v1/iam/certs/get?owner=admin&name=" + signingKid, "", 200},
		{"the cert it names, under the org it serves", "GET",
			"/v1/iam/certs/get?owner=hanzo&name=" + signingKid, "", 200},
		// The LIST route is not the self-read. ApplicationQuery carries only Owner,
		// so a name is not a filter here and this asks to enumerate EVERY
		// application under the reserved admin org — which a tenant app may not do.
		// 403 is the right answer and the policy agreeing with itself.
		{"a LIST of a reserved org is refused", "GET", "/v1/iam/applications?owner=admin&name=hanzo-cloud", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.basic(t, tc.method, tc.path, tc.body, "hanzo-cloud", "s3cret"); got != tc.want {
				t.Errorf("%s %s as hanzo-cloud = %d, want %d", tc.method, tc.path, got, tc.want)
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
	seedCertRow(t, h.db, "admin", "cert-lux")

	for _, tc := range []struct{ name, method, path, body string }{
		{"a sibling application", "GET", "/v1/iam/applications/get?owner=admin&name=hanzo-console", ""},
		{"same name, tenant owner", "GET", "/v1/iam/applications/get?owner=hanzo&name=hanzo-cloud", ""},
		{"a cert it does not reference", "GET", "/v1/iam/certs/get?owner=admin&name=cert-lux", ""},
		{"the whole application list", "GET", "/v1/iam/applications?owner=admin", ""},
		{"the whole cert list", "GET", "/v1/iam/certs?owner=admin", ""},
		{"a user row", "GET", "/v1/iam/users?owner=admin", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.basic(t, tc.method, tc.path, tc.body, "hanzo-cloud", "s3cret"); got == 200 {
				t.Errorf("%s %s as hanzo-cloud was ADMITTED (200); self-read must not widen", tc.method, tc.path)
			}
		})
	}
}

// A bad client secret is still not a principal at all.
func TestSelfRead_WrongSecretIsNotAPrincipal(t *testing.T) {
	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)
	const own = "/v1/iam/applications/get?owner=admin&name=hanzo-cloud"
	if got := h.basicGet(t, own, "hanzo-cloud", "wrong"); got == 200 {
		t.Errorf("a wrong client secret read the application row")
	}
}

// A 200 carrying nothing is not a fix. Assert the row actually comes back — that
// is the failure the first probe of this grant caught, and a status code alone
// would not have caught it.
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

	if resp.StatusCode != 200 {
		t.Fatalf("self-read = %d: %s", resp.StatusCode, body)
	}

	// The native surface answers with the entity itself, not an envelope around
	// it, so the fields are read at the top level.
	var got struct {
		Name  string `json:"name"`
		Owner string `json:"owner"`
		Cert  string `json:"cert"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if got.Owner != "admin" || got.Name != "hanzo-cloud" {
		t.Errorf("got %s/%s, want admin/hanzo-cloud — body %s", got.Owner, got.Name, body)
	}
	if got.Cert != signingKid {
		t.Errorf("cert = %q, want %q — the caller reads this next", got.Cert, signingKid)
	}
}

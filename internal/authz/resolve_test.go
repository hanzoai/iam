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
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// THE TWO KEY DOORS.
//
// An opaque key is resolved to what it authorizes, and there are two doors
// because there are two kinds of key: a publishable pk- names only the ORG that
// holds it, a secret sk- names the principal. That difference is the whole reason
// a pk- is safe to ship in client JavaScript, so it is the property worth pinning
// — not the routing.
//
// Both are on the request-authentication path: cloud, ai and base all resolve an
// API key through one of them on the way to serving a request. They were served
// only by the retired verb surface, and restoring them without tests would have
// left the estate's authentication boundary resting on a path swap nobody checked.
//
// The gate is service-only by construction: a caller must be a confidential app
// holding the capability. A human — even a SuperAdmin — is refused, because a
// capability is held vacuously by a non-app and key resolution is a machine
// boundary, never an interactive admin action.

const (
	publishablePath = "/v1/iam/keys/org"
	principalPath   = "/v1/iam/keys/principal"
)

// basicBody issues a request with client_secret_basic and decodes the answer.
// These two doors kept the envelope their handlers always wrote, so the verdict
// is in the body's `status`, not only in the HTTP code.
func (h *harness) basicBody(t *testing.T, method, path, clientID, secret string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return body
}

// seedKey writes a key row the way a mint does. `user` is the principal the key
// speaks for, spelled "<owner>/<name>" — a secret key resolves through it, and
// the store refuses one naming a user outside the key's own tenant.
func seedKey(t *testing.T, db orm.DB, owner, name, access, secret, scope, user string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name = owner, name
	k.AccessKey, k.AccessSecret, k.Scope, k.User = access, secret, scope, user
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed key %s/%s: %v", owner, name, err)
	}
}

// keyholder registers the app both doors are opened for and returns its Basic
// credential.
func keyholder(t *testing.T, h *harness) (id, secret string) {
	t.Helper()
	t.Setenv("IAM_KEY_RESOLVE_APPS", "hanzo-cloud")
	t.Setenv("IAM_PUBLISHABLE_RESOLVE_APPS", "hanzo-cloud")
	seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)
	return "hanzo-cloud", "s3cret"
}

// A publishable key names its org and nothing else.
func TestResolve_publishableNamesTheOrgOnly(t *testing.T) {
	h := newHarness(t)
	id, secret := keyholder(t, h)
	seedKey(t, h.db, "lux", "browser", "pk-live-abc", "", string(schema.KeyScopePublish), "")

	body := h.basicBody(t, "GET", publishablePath+"?accessKey=pk-live-abc", id, secret)
	if got := body["status"]; got != "ok" {
		t.Fatalf("resolving a live publishable key answered %v: %v", got, body)
	}
	data, _ := body["data"].(map[string]any)
	if data["org"] != "lux" {
		t.Errorf("org = %v, want lux", data["org"])
	}
	// THE property: an org, never a person. A key shipped in client code cannot
	// become a way to learn who anyone is.
	for _, field := range []string{"name", "email", "isAdmin", "owner", "billing_account"} {
		if _, present := data[field]; present {
			t.Errorf("the publishable projection carries %q — a pk- must name an org and no principal: %v",
				field, data)
		}
	}
}

// A SECRET key resolves to the principal, and to the payer, because who pays
// travels with the identity or it is guessed.
func TestResolve_secretNamesThePrincipal(t *testing.T) {
	h := newHarness(t)
	id, secret := keyholder(t, h)
	seedUser(t, h.db, "lux", "alice", false, false, false)
	seedKey(t, h.db, "lux", "alice-cli", "pk-live-def", "sk-live-def", "", "lux/alice")

	body := h.basicBody(t, "GET", principalPath+"?accessKey=sk-live-def", id, secret)
	if got := body["status"]; got != "ok" {
		t.Fatalf("resolving a live secret key answered %v: %v", got, body)
	}
	data, _ := body["data"].(map[string]any)
	if data["owner"] != "lux" || data["name"] != "alice" {
		t.Errorf("got %v/%v, want lux/alice", data["owner"], data["name"])
	}
	// A secret must never come back from a door that only takes one.
	for _, field := range []string{"accessSecret", "password", "passwordHash", "accessKey"} {
		if _, present := data[field]; present {
			t.Errorf("the principal projection carries %q: %v", field, data)
		}
	}
}

// Each door refuses the OTHER kind of key. They are not interchangeable, and the
// asymmetry is the point: presenting a pk- to the secret door must not yield a
// principal, and presenting an sk- to the publishable door must not yield an org.
func TestResolve_eachDoorRefusesTheOtherKind(t *testing.T) {
	h := newHarness(t)
	id, secret := keyholder(t, h)
	seedUser(t, h.db, "lux", "alice", false, false, false)
	seedKey(t, h.db, "lux", "browser", "pk-live-abc", "", string(schema.KeyScopePublish), "")
	seedKey(t, h.db, "lux", "alice-cli", "pk-live-def", "sk-live-def", "", "lux/alice")

	for _, tc := range []struct{ name, path, key string }{
		{"a secret key at the publishable door", publishablePath, "sk-live-def"},
		{"a publishable key at the secret door", principalPath, "pk-live-abc"},
		{"a value that is no key at all", principalPath, "nonsense"},
		{"an unknown key", publishablePath, "pk-live-nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := h.basicBody(t, "GET", tc.path+"?accessKey="+tc.key, id, secret)
			if body["status"] == "ok" {
				t.Errorf("%s resolved: %v", tc.name, body)
			}
		})
	}
}

// An expired publishable key is refused, and revocation is deletion, so a live
// row is a live key. Fail-closed: a lifetime that cannot be read is expired.
func TestResolve_anExpiredKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	id, secret := keyholder(t, h)

	k := orm.New[schema.Key](h.db)
	k.Owner, k.Name = "lux", "stale"
	k.AccessKey, k.Scope = "pk-live-old", string(schema.KeyScopePublish)
	k.ExpireTime = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	k.SetId("lux/stale")
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := h.basicBody(t, "GET", publishablePath+"?accessKey=pk-live-old", id, secret)
	if body["status"] == "ok" {
		t.Errorf("an expired publishable key resolved: %v", body)
	}
}

// THE GATE. Neither door opens for a caller that does not hold its capability,
// and holding one is not holding the other — they disclose different amounts.
func TestResolve_theGateIsPerCapability(t *testing.T) {
	for _, tc := range []struct {
		name, env, path string
	}{
		{"the secret door needs CapKeyResolve", "IAM_PUBLISHABLE_RESOLVE_APPS", principalPath},
		{"the publishable door needs CapPublishableResolve", "IAM_KEY_RESOLVE_APPS", publishablePath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			// Hold only the OTHER capability.
			t.Setenv(tc.env, "hanzo-cloud")
			seedAppRow(t, h.db, "admin", "hanzo-cloud", "s3cret", signingKid)
			seedUser(t, h.db, "lux", "alice", false, false, false)
			seedKey(t, h.db, "lux", "browser", "pk-live-abc", "", string(schema.KeyScopePublish), "")
			seedKey(t, h.db, "lux", "alice-cli", "pk-live-def", "sk-live-def", "", "lux/alice")

			for _, key := range []string{"pk-live-abc", "sk-live-def"} {
				body := h.basicBody(t, "GET", tc.path+"?accessKey="+key, "hanzo-cloud", "s3cret")
				if body["status"] == "ok" {
					t.Errorf("%s opened for a caller holding only the other capability (%s): %v",
						tc.path, key, body)
				}
			}
		})
	}
}

// A HUMAN is refused, whatever authority they hold. A capability is held
// vacuously by a non-app, so a bearer token must not reach either door — that is
// what keeps key resolution a machine boundary rather than an admin action.
func TestResolve_aHumanIsRefusedEvenAsSuperAdmin(t *testing.T) {
	h := newHarness(t)
	keyholder(t, h)
	seedKey(t, h.db, "lux", "browser", "pk-live-abc", "", string(schema.KeyScopePublish), "")

	root := h.token(t, "admin/root")
	for _, path := range []string{publishablePath, principalPath} {
		if got := h.do(t, "GET", path+"?accessKey=pk-live-abc", root, nil); got == 200 {
			t.Errorf("GET %s as a SuperAdmin human answered 200; both doors are service-only", path)
		}
	}
}

// An unauthenticated caller reaches neither. The doors are handler-authorized,
// which exempts them from the Guard's ENTITY check and from nothing else.
func TestResolve_unauthenticatedReachesNeither(t *testing.T) {
	h := newHarness(t)
	keyholder(t, h)
	seedKey(t, h.db, "lux", "browser", "pk-live-abc", "", string(schema.KeyScopePublish), "")

	for _, path := range []string{publishablePath, principalPath} {
		if got := h.do(t, "GET", path+"?accessKey=pk-live-abc", "", nil); got == 200 {
			t.Errorf("GET %s with no credential answered 200", path)
		}
	}
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// The whole life of a user's API key, over the mounted router: a confidential
// client mints one at /v1/iam/users/{owner}/{name}/keys, and the credential that
// comes back is presented at /v1/iam/keys/principal — the address every service
// in the estate turns a key into an identity with.
//
// The two ends have to be driven TOGETHER or neither is tested. Reading the key
// row back proves only that a row exists; a row can hold the right digest and
// still answer for nobody, and a row can be written and be invisible. The mint
// returned 200 with a live sk- while the resolver answered key_unknown for it,
// and every test that stopped at the row was green throughout.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

const (
	minterApp    = "hanzo-console" // confidential client on the mint allow-list
	minterSecret = "console-secret"
	userKeys     = "/v1/iam/users/hanzo/alice/keys"
)

// mintEnv decodes the mint envelope. AccessKey carries whichever half the
// requested key type presents — the sk- for a secret key, the pk- for a
// publishable one.
type mintEnv struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Data   struct {
		AccessKey string `json:"accessKey"`
	} `json:"data"`
}

// mintFixtures arms the two allow-lists and seeds the client that holds them:
// one app to mint on a user's behalf, one to resolve what was minted.
func mintFixtures(t *testing.T, h *harness) {
	t.Helper()
	seedClientApp(t, h.db, minterApp, minterSecret)
	seedClientApp(t, h.db, resolverApp, svcSecret)
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", minterApp)
	t.Setenv("IAM_KEY_RESOLVE_APPS", resolverApp)
}

// mint drives one mint as the confidential client and returns the presented half.
func mint(t *testing.T, h *harness, path string) string {
	t.Helper()
	req := httptest.NewRequest("POST", path, nil)
	req.Host = "hanzo.id"
	req.SetBasicAuth(minterApp, minterSecret)
	status, body := h.do(t, req)
	var env mintEnv
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("mint %s: %d %s", path, status, body)
	}
	if env.Data.AccessKey == "" {
		t.Fatalf("mint %s returned no key: %d %s", path, status, body)
	}
	return env.Data.AccessKey
}

// revoke drives the mint's dual at the same address.
func revoke(t *testing.T, h *harness, path string) {
	t.Helper()
	req := httptest.NewRequest("DELETE", path, nil)
	req.Host = "hanzo.id"
	req.SetBasicAuth(minterApp, minterSecret)
	if status, body := h.do(t, req); status != 200 {
		t.Fatalf("revoke %s: %d %s", path, status, body)
	}
}

// whoHolds presents a secret at the principal endpoint and returns the answer.
func whoHolds(t *testing.T, h *harness, secret string) keyEnv {
	t.Helper()
	_, body := h.getBasic(t, principalDoor+secret, resolverApp, svcSecret)
	var env keyEnv
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("resolve: %s", body)
	}
	return env
}

// A minted key authenticates its user — the mint's whole promise, asked at the
// address that keeps it.
func TestMintedUserKeyAuthenticates(t *testing.T) {
	h := newHarness(t)
	mintFixtures(t, h)

	got := whoHolds(t, h, mint(t, h, userKeys))
	if got.Data.Owner != "hanzo" || got.Data.Name != "alice" {
		t.Fatalf("the minted key resolved to %q/%q (code %q, msg %q), want hanzo/alice",
			got.Data.Owner, got.Data.Name, got.Code, got.Msg)
	}
}

// And it still does after the previous one was revoked. A revoke leaves the store
// holding a deleted row under the same deterministic id, so the mint that follows
// writes onto that row: the response carried a live sk- while the row it was
// written to stayed deleted, and no reader could see it. Re-minting never helped —
// the user's key was gone for good, from their first revoke onward.
func TestMintedUserKeyAuthenticatesAfterARevoke(t *testing.T) {
	h := newHarness(t)
	mintFixtures(t, h)

	first := mint(t, h, userKeys)
	revoke(t, h, userKeys)

	// The revoked one is gone, which is the other half of the promise.
	if got := whoHolds(t, h, first); got.Data.Name != "" {
		t.Fatalf("a revoked key still authenticates %q/%q", got.Data.Owner, got.Data.Name)
	}

	got := whoHolds(t, h, mint(t, h, userKeys))
	if got.Data.Owner != "hanzo" || got.Data.Name != "alice" {
		t.Fatalf("the key minted after a revoke resolved to %q/%q (code %q), want hanzo/alice",
			got.Data.Owner, got.Data.Name, got.Code)
	}
}

// The publishable key is the same story at the other door: it names an org and
// never a person, so a fresh one must answer at the org endpoint after a revoke.
func TestMintedPublishableKeyResolvesItsOrgAfterARevoke(t *testing.T) {
	h := newHarness(t)
	mintFixtures(t, h)
	t.Setenv("IAM_PUBLISHABLE_RESOLVE_APPS", resolverApp)

	const publishable = userKeys + "?type=publishable"
	mint(t, h, publishable)
	revoke(t, h, publishable)

	_, body := h.getBasic(t, orgDoor+mint(t, h, publishable), resolverApp, svcSecret)
	var got resolveEnv
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("resolve: %s", body)
	}
	if got.Data.Org != "hanzo" {
		t.Fatalf("the publishable key minted after a revoke resolved to org %q: %s", got.Data.Org, body)
	}
	if got.Data.Name != "" || got.Data.Email != "" {
		t.Fatalf("the org endpoint disclosed a principal: %s", body)
	}
}

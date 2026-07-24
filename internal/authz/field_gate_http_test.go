// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz_test

// End-to-end proof (F1a) that the application field gate holds on the REAL wire the
// attacker uses: POST /v1/iam/add-application and /v1/iam/update-application, through the
// mounted Guard + op-invoke authorizer + the applications CRUD. EnableAutoSignin, IsShared
// and OrgChoiceMode are the fields that arm the /oauth/authorize login-CSRF; the op-seam
// authorizes only the app's Owner, so a tenant admin's own-org write is ALLOWED (200) —
// the gate must therefore neutralize the FIELDS, not the request. A SuperAdmin sets them.

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/internal/store"
)

// appByClientId loads the persisted application by its global clientId — the real security
// property behind a 200 is what got WRITTEN, not the status.
func appByClientId(t *testing.T, h *harness, clientId string) (autosignin, shared bool, orgChoice string) {
	t.Helper()
	a, err := store.GetApplicationByClientId(context.Background(), h.db, clientId)
	if err != nil || a == nil {
		t.Fatalf("expected application clientId=%q to exist: %v", clientId, err)
	}
	return a.EnableAutoSignin, a.IsShared, a.OrgChoiceMode
}

// A non-super org admin (boss@hanzo) registers an app in its OWN org carrying every minting
// flag plus an attacker callback. The own-org write is authorized (200), but the three
// flags MUST land off — the app is inert as an SSO surface. FAIL-BEFORE: the gate did not
// exist, so a 200 persisted enableAutoSignin=true, isShared=true, orgChoiceMode=user and an
// evil redirect — the fully-armed login-CSRF app. This is step (1) of Red's exploit chain.
func TestFieldGateHTTP_NonSuperAddApplication_FlagsForcedOff(t *testing.T) {
	h := newHarness(t)
	body := map[string]any{
		"owner": "hanzo", "name": "evil", "organization": "hanzo", "clientId": "evil",
		"enableAutoSignin": true, "isShared": true, "orgChoiceMode": "user",
		"redirectUris": []string{"https://evil.example/cb"},
	}
	if code := h.do(t, "POST", "/v1/iam/add-application", h.token(t, "hanzo/boss"), body); code != 200 {
		t.Fatalf("own-org add-application status=%d, want 200 (the write is allowed; the FIELDS are gated)", code)
	}
	autosignin, shared, orgChoice := appByClientId(t, h, "evil")
	if autosignin || shared || orgChoice != "" {
		t.Fatalf("F1a REOPENED on the wire: add-application persisted the minting flags "+
			"(enableAutoSignin=%v isShared=%v orgChoiceMode=%q) — the login-CSRF app is armed", autosignin, shared, orgChoice)
	}
}

// The same tenant tries to FLIP the flags on a benign app it already owns (step 1, update
// variant). The update is authorized (own org) but the stored-off values are preserved.
// FAIL-BEFORE: the flip persisted, arming the app after the fact.
func TestFieldGateHTTP_NonSuperUpdateApplication_FlagsPreserved(t *testing.T) {
	h := newHarness(t)
	// Create the benign app first (flags already forced off by the same gate).
	seed := map[string]any{"owner": "hanzo", "name": "app", "organization": "hanzo", "clientId": "app"}
	if code := h.do(t, "POST", "/v1/iam/add-application", h.token(t, "hanzo/boss"), seed); code != 200 {
		t.Fatalf("seed benign app status=%d, want 200", code)
	}
	flip := map[string]any{
		"owner": "hanzo", "name": "app", "organization": "hanzo", "clientId": "app",
		"enableAutoSignin": true, "isShared": true, "orgChoiceMode": "user",
	}
	if code := h.do(t, "POST", "/v1/iam/update-application", h.token(t, "hanzo/boss"), flip); code != 200 {
		t.Fatalf("own-org update-application status=%d, want 200", code)
	}
	autosignin, shared, orgChoice := appByClientId(t, h, "app")
	if autosignin || shared || orgChoice != "" {
		t.Fatalf("F1a REOPENED on the wire: update-application flipped the minting flags on "+
			"(enableAutoSignin=%v isShared=%v orgChoiceMode=%q)", autosignin, shared, orgChoice)
	}
}

// A SuperAdmin (root@admin) registers a platform app WITH enableAutoSignin — the legitimate
// console/commerce silent-SSO case. Gating to SuperAdmin must not neutralize a super's
// write, or every platform SSO app breaks.
func TestFieldGateHTTP_SuperAddApplication_FlagsKept(t *testing.T) {
	h := newHarness(t)
	body := map[string]any{
		"owner": "admin", "name": "hanzo-commerce", "organization": "hanzo", "clientId": "hanzo-commerce",
		"enableAutoSignin": true,
	}
	if code := h.do(t, "POST", "/v1/iam/add-application", h.token(t, "admin/root"), body); code != 200 {
		t.Fatalf("super add-application status=%d, want 200", code)
	}
	if autosignin, _, _ := appByClientId(t, h, "hanzo-commerce"); !autosignin {
		t.Fatal("a SuperAdmin's enableAutoSignin was neutralized on the wire (would break platform SSO)")
	}
}

// Tenant isolation is unchanged: a non-super still cannot even reach the field gate for a
// FOREIGN org's app — the op-invoke seam refuses the cross-tenant write (403). Confirms the
// field gate is defense in depth layered behind the existing owner authorization, not a
// replacement for it.
func TestFieldGateHTTP_NonSuperForeignOrg_StillForbidden(t *testing.T) {
	h := newHarness(t)
	body := map[string]any{"owner": "orgb", "name": "x", "organization": "orgb", "clientId": "x", "enableAutoSignin": true}
	if code := h.do(t, "POST", "/v1/iam/add-application", h.token(t, "hanzo/boss"), body); code != 403 {
		t.Fatalf("cross-tenant add-application status=%d, want 403 (op-seam owner gate)", code)
	}
}

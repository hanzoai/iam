// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const scimPassword = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"password","value":"a whole new password"}]}`

// SCIM is a second write surface for the same row. The branch covers it for an
// application; an org admin reaches SCIM through the same tenant rule.
func TestRed_SuperAdmin_OrgAdminCannotWriteThroughSCIM(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	boss := h.person(t, "hanzo/boss")

	if status, body := h.send(t, boss, "PATCH", "/v1/iam/scim/v2/Users/hanzo/z", scimPassword); status != 403 {
		t.Errorf("SCIM PATCH of the operator's password as hanzo's admin answered %d: %s", status, body)
	}
	if got := digest(t, h, "hanzo", "z"); got != secretUserHash {
		t.Errorf("the operator's password changed through SCIM")
	}
	replace := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"z","emails":[{"value":"taken@evil.test","primary":true}]}`
	if status, body := h.send(t, boss, "PUT", "/v1/iam/scim/v2/Users/hanzo/z", replace); status != 403 {
		t.Errorf("SCIM PUT of the operator as hanzo's admin answered %d: %s", status, body)
	}
	if status, body := h.send(t, boss, "DELETE", "/v1/iam/scim/v2/Users/hanzo/z", ""); status != 403 {
		t.Errorf("SCIM DELETE of the operator as hanzo's admin answered %d: %s", status, body)
	}
	if digest(t, h, "hanzo", "z") == "" {
		t.Errorf("the operator's account was deleted through SCIM")
	}
}

// Filing a passkey for the operator is refused; removing one is not asked.
func TestRed_SuperAdmin_OrgAdminCannotRemoveTheirPasskeyOrToken(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	boss := h.person(t, "hanzo/boss")
	ctx := context.Background()

	pk := orm.New[schema.WebauthnCredential](h.db)
	pk.Owner, pk.Name, pk.User = "hanzo", "operator-key", "hanzo/z"
	pk.SetId("hanzo/operator-key")
	if err := pk.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if status, body := h.send(t, boss, "DELETE", "/v1/iam/webauthn-credentials/hanzo/operator-key", ""); status == 200 {
		if _, err := orm.Get[schema.WebauthnCredential](h.db, "hanzo/operator-key"); err != nil {
			t.Errorf("hanzo's admin removed the operator's passkey: %d %s", status, body)
		}
	}

	tok := orm.New[schema.Token](h.db)
	tok.Owner, tok.Name, tok.User = "hanzo", "operator-session", "hanzo/z"
	tok.SetId("hanzo/operator-session")
	if err := tok.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if status, body := h.send(t, boss, "DELETE", "/v1/iam/tokens/hanzo/operator-session", ""); status == 200 {
		if _, err := orm.Get[schema.Token](h.db, "hanzo/operator-session"); err != nil {
			t.Errorf("hanzo's admin revoked the operator's token: %d %s", status, body)
		}
	}
}

// The known gap, pinned: an org admin mints an API key whose holder is the
// operator anchored in that org, and the key resolves to the operator's row.
func TestRed_SuperAdmin_OrgAdminCannotMintAKeyForThem(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	boss := h.person(t, "hanzo/boss")

	status, body := h.send(t, boss, "POST", "/v1/iam/keys", `{"owner":"hanzo","name":"planted","user":"z"}`)
	if status != 200 {
		return // refused: the gap is closed
	}
	var e struct {
		Data struct {
			AccessSecret string `json:"accessSecret"`
		} `json:"data"`
		AccessSecret string `json:"accessSecret"`
	}
	_ = json.Unmarshal([]byte(body), &e)
	secret := e.Data.AccessSecret
	if secret == "" {
		secret = e.AccessSecret
	}
	u, err := store.UserByAccessKey(context.Background(), h.db, secret)
	if err == nil && u != nil {
		super, _ := store.IsSuperAdmin(context.Background(), h.db, u.Owner, u.Name)
		t.Errorf("hanzo's admin minted a key that resolves to %s/%s (SuperAdmin=%v)", u.Owner, u.Name, super)
	}
}

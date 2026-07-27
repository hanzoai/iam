// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// Red-team helpers + the field-preservation guard for the on-behalf-of primitives.
// The name-collision priv-esc PoC that motivated the clientId-only allow-list is
// now the regression guard TestTokenExchange_nameCollisionAttacker_403 (the
// issue-user-token verb it originally attacked is retired in favor of RFC 8693
// Token Exchange). seedAttackerApp stays here — it models exactly what a tenant
// org-admin can create through POST /v1/iam/application (every field bound from
// the body), the precondition that test relies on.

// seedAttackerApp creates a tenant-owned application the attacker fully controls
// (owner=evil, chosen name/clientId/secret) whose Cert points at an EXISTING
// trusted platform cert by name — exactly what internal/applications.create binds
// from the request body (Owner/Name/ClientId/ClientSecret/Cert all verbatim).
func seedAttackerApp(t *testing.T, db orm.DB, owner, name, clientID, secret, platformCert string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner = owner // a NON-reserved tenant org the attacker org-admins
	a.Name = name
	a.ClientId = clientID
	a.ClientSecret = secret
	a.Organization = owner
	a.Cert = platformCert // resolved among admin/built-in by GetSigningCert
	a.ExpireInHours = 1
	a.SetId(owner + "/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed attacker app: %v", err)
	}
}

// TestRedTeam_mintKeys_preservesPasswordHashAndIsAdmin proves the mint/revoke
// read-modify-write (updateUser) does not blank PasswordHash nor flip privilege
// bits. updateUser reads the FULL row fresh under a row lock and mutates only
// AccessKey/UpdatedTime, so every field the handler didn't touch is preserved.
func TestRedTeam_mintKeys_preservesPasswordHashAndIsAdmin(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = "hanzo", "carol", "carol@hanzo.ai"
	u.PasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$SALTSALT$HASHHASHHASH"
	u.PasswordType = "argon2id"
	u.IsAdmin = true
	u.SetId("hanzo/carol")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if resp, body := do(t, app, keyReq(PathMintUserKeys, "hanzo-console", "top-secret", "?id=hanzo/carol")); resp.StatusCode != 200 {
		t.Fatalf("mint status=%d body=%s", resp.StatusCode, body)
	}

	got, err := orm.Get[schema.User](db, "hanzo/carol")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.PasswordHash != u.PasswordHash {
		t.Errorf("PasswordHash mutated by mint: %q", got.PasswordHash)
	}
	if got.PasswordType != "argon2id" {
		t.Errorf("PasswordType mutated by mint: %q", got.PasswordType)
	}
	if !got.IsAdmin {
		t.Errorf("IsAdmin flipped false by mint")
	}
	// The credential no longer lives on the user row — it is a schema.Key the
	// resolver reads. What this red-team test guards is that mint does not mutate
	// the user's OTHER fields, which is asserted above.
}

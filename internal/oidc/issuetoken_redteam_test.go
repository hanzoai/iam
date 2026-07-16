// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
)

// RED TEAM PoC — throwaway. Proves the mintAllowed() name-collision bypass:
// the allow-list is matched against app.NAME as well as clientId, but app names
// are unique only per-owner (Application key = owner/name), while clientId is
// global. An attacker who controls ANY app named like the allow-listed console
// authenticates with their OWN (non-allow-listed) clientId + secret, passes the
// allow-list via the NAME, points the app's Cert at the platform signing cert,
// and mints a fully-valid owner="admin" SuperAdmin token.

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

// seedAdminUser seeds a real SuperAdmin principal (admin org, IsAdmin) — the
// target whose authority the attacker steals.
func seedAdminUser(t *testing.T, db orm.DB, name string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner = "admin"
	u.Name = name
	u.Email = name + "@hanzo.ai"
	u.IsAdmin = true
	u.SetId("admin/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
}

// TestRedTeam_mintAllowedNameCollision_privEsc is the regression guard for the
// closed CRITICAL: the exact attack — an attacker app named like the allow-listed
// console but with the attacker's OWN clientId — must now be REFUSED. mintAllowed
// matches the globally-unique clientId only, so the NAME collision no longer
// admits, and the request is rejected at the allow-list before any token is minted.
func TestRedTeam_mintAllowedNameCollision_privEsc(t *testing.T) {
	// The operator allow-lists the console by its convention identity "hanzo-console"
	// (which IS both the real console's clientId AND its name, per <org>-<app>).
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)

	// The legit console — seeded ONLY so its admin-owned platform cert
	// "cert-hanzo-console" exists. The attacker never learns this app's secret.
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	// The attacker's own app: a DIFFERENT clientId ("evil-pwn", NOT allow-listed),
	// a secret THEY chose, but NAME == "hanzo-console" and Cert aimed at the
	// platform key — exactly what an org-admin of "evil" can create.
	seedAttackerApp(t, db, "evil", "hanzo-console", "evil-pwn", "attacker-knows-this", "cert-hanzo-console")
	seedAdminUser(t, db, "root")

	resp, body := do(t, app, issueReq("evil-pwn", "attacker-knows-this",
		"?id=admin/root&aud=hanzo-cloud"))

	// Closed: the name collision no longer admits an off-allow-list clientId.
	if resp.StatusCode != 403 {
		t.Fatalf("PRIV-ESC REOPENED: attacker clientId %q admitted (status=%d) — mintAllowed must match clientId only; body=%s",
			"evil-pwn", resp.StatusCode, body)
	}
	if token, _ := dataMap(t, body)["accessToken"].(string); token != "" {
		t.Fatalf("a token was minted for an off-allow-list client: %q", token)
	}
}

// TestRedTeam_reservedOrgTarget_requiresAdminCapability proves the defense-in-depth
// layer: even a validly allow-listed general minter cannot mint for a RESERVED-org
// (admin) user unless it also holds the separate admin-mint capability — so a
// leaked general-minter secret can never reach a SuperAdmin identity.
func TestRedTeam_reservedOrgTarget_requiresAdminCapability(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console") // general mint OK
	// IAM_ADMIN_MINT_ALLOWED_APPS intentionally UNSET → no reserved-org minting.
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedAdminUser(t, db, "root")

	resp, body := do(t, app, issueReq("hanzo-console", "top-secret", "?id=admin/root&aud=hanzo-cloud"))
	if resp.StatusCode != 403 {
		t.Fatalf("reserved-org target admitted without admin capability: status=%d body=%s", resp.StatusCode, body)
	}
}

// TestRedTeam_reservedOrgTarget_admitsWithAdminCapability confirms the LEGITIMATE
// admin-console flow still works: a client on BOTH lists mints an admin-org token
// (the operator driving admin.hanzo.ai).
func TestRedTeam_reservedOrgTarget_admitsWithAdminCapability(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	t.Setenv("IAM_ADMIN_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedAdminUser(t, db, "root")

	resp, body := do(t, app, issueReq("hanzo-console", "top-secret", "?id=admin/root&aud=hanzo-cloud"))
	if resp.StatusCode != 200 {
		t.Fatalf("legit admin-console mint refused: status=%d body=%s", resp.StatusCode, body)
	}
	if access, _ := dataMap(t, body)["accessToken"].(string); access == "" {
		t.Fatalf("no admin token minted for the capability-holding client; body=%s", body)
	}
}

// TestRedTeam_control_differentName_isRejected is the control: the SAME attacker
// clientId+secret, but an app NAME that does not collide, is correctly refused —
// proving the ONLY thing that admitted the attacker above was the NAME match.
func TestRedTeam_control_differentName_isRejected(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedAttackerApp(t, db, "evil", "evil-app", "evil-pwn", "attacker-knows-this", "cert-hanzo-console")
	seedAdminUser(t, db, "root")

	resp, _ := do(t, app, issueReq("evil-pwn", "attacker-knows-this", "?id=admin/root"))
	if resp.StatusCode != 403 {
		t.Fatalf("control: status=%d, want 403 (non-colliding name must be off the allow-list)", resp.StatusCode)
	}
}

// TestRedTeam_mintKeys_preservesPasswordHashAndIsAdmin verifies threat-D is SAFE:
// the mint/revoke read-modify-write (saveUser) must not blank PasswordHash nor
// flip privilege bits. GetUserByName returns the FULL row (store applies no mask),
// so *existing = *user preserves every field the handler didn't touch.
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

	mint := issueReq("hanzo-console", "top-secret", "?id=hanzo/carol")
	mint.URL.Path = PathMintUserKeys
	if resp, body := do(t, app, mint); resp.StatusCode != 200 {
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
	if got.AccessKey == "" {
		t.Errorf("mint did not set AccessKey")
	}
}

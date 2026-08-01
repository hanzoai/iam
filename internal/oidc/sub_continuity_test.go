// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// SUB CONTINUITY (cutover parity). A migrated user carries the v1 the legacy surface UUID in
// schema.User.Id; every token, id_token, and userinfo response must report that
// UUID as `sub` — byte-identical across the cutover — so sessions, external refs,
// and the money-path principal keyed on `sub` survive. A pre-cutover user with no
// Id falls back to the (owner/name) natural key.

// seedUserWithId seeds a password user in org hanzo carrying an explicit Id (the
// migrated continuity subject). An empty id leaves the row without one (the
// fallback case).
func seedUserWithId(t *testing.T, db orm.DB, name, id, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Id = id
	u.Owner = "hanzo"
	u.Name = name
	u.Email = name + "@hanzo.ai"
	u.PasswordHash = string(hash)
	u.PasswordType = "bcrypt"
	u.SetId("hanzo/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %q: %v", name, err)
	}
}

func TestSubContinuity_migratedUserMintsUUIDSubject(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	const uuid = "e7d7fda0-4c53-4508-9d35-7ec892b7e5d7"
	seedUserWithId(t, db, "z", uuid, "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"z"},
		"password":      {"correct horse"},
		"scope":         {"openid profile email"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200; body=%v", resp.StatusCode, tok)
	}

	// The access token's `sub` is the UUID — not "hanzo/z".
	access, _ := tok["access_token"].(string)
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("access token does not verify: %v", err)
	}
	if claims.Subject != uuid {
		t.Errorf("access sub = %q, want the migrated UUID %q", claims.Subject, uuid)
	}
	// Tenancy is still carried by the owner claim.
	if claims.Owner != "hanzo" {
		t.Errorf("owner = %q, want hanzo", claims.Owner)
	}

	// The id_token carries the SAME subject.
	idt, _ := tok["id_token"].(string)
	if idt == "" {
		t.Fatal("openid requested but no id_token minted")
	}
	idClaims, err := verifyToken(context.Background(), db, idt)
	if err != nil {
		t.Fatalf("id_token does not verify: %v", err)
	}
	if idClaims.Subject != uuid {
		t.Errorf("id_token sub = %q, want %q", idClaims.Subject, uuid)
	}

	// userinfo reports the SAME sub.
	status, info := userinfo(t, app, access)
	if status != 200 {
		t.Fatalf("userinfo status = %d, body %v", status, info)
	}
	if info["sub"] != uuid {
		t.Errorf("userinfo sub = %v, want %q", info["sub"], uuid)
	}
}

func TestSubContinuity_userWithoutIdFallsBackToOwnerName(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUserWithId(t, db, "legacy", "", "correct horse") // no Id → fallback

	_, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"legacy"},
		"password":      {"correct horse"},
		"scope":         {"openid"},
	})
	access, _ := tok["access_token"].(string)
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	if claims.Subject != "hanzo/legacy" {
		t.Errorf("sub = %q, want the owner/name fallback hanzo/legacy", claims.Subject)
	}
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package tokens

// A token row names a SUBJECT (User) and carries the credential hashes a presented
// bearer or refresh token is resolved by. Neither is the row's (Owner, Name) key,
// so neither is covered by the op-invoke seam that authorizes it — the write must
// authorize the subject itself, and must never let a caller choose a credential
// hash. These drive the handlers directly with a bound principal, the way
// probe_test.go drives the rest of this surface.

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// hanzoAdmin is an org-admin of hanzo — it may act for its own members, never for
// a reserved-org user.
func hanzoAdmin() context.Context {
	return principal.Bind(context.Background(), &principal.Principal{Org: "hanzo", User: "boss", Admin: true})
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("error %v is not a *zip.HTTPError", err)
	}
	return he.Status
}

func seedWithHash(t *testing.T, db orm.DB, owner, name, user, refreshHash string) {
	t.Helper()
	tok := orm.New[schema.Token](db)
	tok.Owner, tok.Name, tok.User, tok.RefreshTokenHash = owner, name, user, refreshHash
	tok.SetId(tokenId(owner, name))
	if err := tok.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

// Step two of the forge chain — a token row whose subject is admin/root — is
// refused: an org-admin may not record a token for a reserved-org user, and the
// row that a refresh redemption would sign never lands.
func TestAdd_refusesATokenForAReservedSubject(t *testing.T) {
	db := openDB(t)
	_, err := addToken(db)(hanzoAdmin(), &schema.Token{
		Owner: "hanzo", Name: "forge", User: "admin/root",
		RefreshTokenHash: "0badc0de", PublicGrant: true, Scope: "openid",
	})
	if err == nil {
		t.Fatal("recording a token for admin/root must be refused")
	}
	if got := statusOf(t, err); got != 403 {
		t.Fatalf("status=%d, want 403", got)
	}
	if _, gerr := orm.Get[schema.Token](db, "hanzo/forge"); gerr == nil {
		t.Fatal("a refused plant persisted a row")
	}
}

// A same-tenant token records fine, but a caller-supplied credential hash is
// ignored: it is the server's to derive, so a chosen refresh hash is never the key
// a presented token resolves by.
func TestAdd_ignoresCallerSuppliedHashes(t *testing.T) {
	db := openDB(t)
	out, err := addToken(db)(hanzoAdmin(), &schema.Token{
		Owner: "hanzo", Name: "own", User: "hanzo/alice",
		RefreshTokenHash: "0badc0de", AccessTokenHash: "0badc0de",
	})
	if err != nil {
		t.Fatalf("recording an own-tenant token: %v", err)
	}
	if out.Token.RefreshTokenHash != "" || out.Token.AccessTokenHash != "" {
		t.Fatalf("caller hashes survived: refresh=%q access=%q", out.Token.RefreshTokenHash, out.Token.AccessTokenHash)
	}
	stored, err := orm.Get[schema.Token](db, "hanzo/own")
	if err != nil {
		t.Fatalf("load stored: %v", err)
	}
	if stored.RefreshTokenHash != "" || stored.AccessTokenHash != "" {
		t.Fatalf("stored row carries a caller hash: refresh=%q access=%q", stored.RefreshTokenHash, stored.AccessTokenHash)
	}
}

// An update cannot overwrite the stored credential hash with a chosen value
// either — a planted refresh hash on an EXISTING row is the same lever.
func TestUpdate_cannotSetTheRefreshHash(t *testing.T) {
	db := openDB(t)
	seedWithHash(t, db, "hanzo", "sess", "hanzo/alice", "realhash")
	out, err := updateToken(db)(hanzoAdmin(), &schema.Token{
		Owner: "hanzo", Name: "sess", User: "hanzo/alice",
		RefreshTokenHash: "0badc0de", Scope: "openid",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Token.RefreshTokenHash != "realhash" {
		t.Fatalf("update changed the refresh hash to %q, want the stored realhash", out.Token.RefreshTokenHash)
	}
}

// An org-admin may still record a token for its OWN member — the subject gate pins
// the identity, it does not break a legitimate write.
func TestAdd_allowsATokenForAnOwnMember(t *testing.T) {
	db := openDB(t)
	if _, err := addToken(db)(hanzoAdmin(), &schema.Token{
		Owner: "hanzo", Name: "own2", User: "hanzo/alice", Scope: "openid",
	}); err != nil {
		t.Fatalf("recording a token for an own member: %v", err)
	}
}

// Code and UserCode are the keys the other two redemptions resolve by: an
// authorization-code exchange finds its row by Code (GetTokenByCode) and a device
// approval finds its row by UserCode, each an unscoped lookup on that one value. A
// chosen code is a chosen grant, so a create carries neither.
func TestAdd_ignoresCallerSuppliedCodes(t *testing.T) {
	db := openDB(t)
	out, err := addToken(db)(hanzoAdmin(), &schema.Token{
		Owner: "hanzo", Name: "grant", User: "hanzo/alice",
		Code: "chosen-code", UserCode: "CHOSEN", Scope: "openid",
	})
	if err != nil {
		t.Fatalf("recording an own-tenant token: %v", err)
	}
	if out.Token.Code != "" || out.Token.UserCode != "" {
		t.Fatalf("caller codes survived: code=%q userCode=%q", out.Token.Code, out.Token.UserCode)
	}
	stored, err := orm.Get[schema.Token](db, "hanzo/grant")
	if err != nil {
		t.Fatalf("load stored: %v", err)
	}
	if stored.Code != "" || stored.UserCode != "" {
		t.Fatalf("stored row carries a caller code: code=%q userCode=%q", stored.Code, stored.UserCode)
	}
}

// Nor can an update overwrite the stored code with a chosen one — planting a code
// on an EXISTING row is the same lever.
func TestUpdate_cannotSetTheCode(t *testing.T) {
	db := openDB(t)
	tok := orm.New[schema.Token](db)
	tok.Owner, tok.Name, tok.User = "hanzo", "sess", "hanzo/alice"
	tok.Code, tok.UserCode = "realcode", "REALUC"
	tok.SetId(tokenId("hanzo", "sess"))
	if err := tok.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, err := updateToken(db)(hanzoAdmin(), &schema.Token{
		Owner: "hanzo", Name: "sess", User: "hanzo/alice",
		Code: "chosen-code", UserCode: "CHOSEN", Scope: "openid",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Token.Code != "realcode" || out.Token.UserCode != "REALUC" {
		t.Fatalf("update changed the codes to %q/%q, want the stored values", out.Token.Code, out.Token.UserCode)
	}
}

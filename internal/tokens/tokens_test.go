// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package tokens

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/schema"
)

func memDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "tokentest.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// R2: the token read projection is masked. getToken and listTokens must never emit
// the plaintext bearers, the SHA-256 verifiers, or the PKCE challenge — only
// non-secret metadata. Fail-before (unmasked handlers): AccessToken="at-secret"
// leaks to any org-admin reader.
func TestReadsAreMasked(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	tok := orm.New[schema.Token](db)
	tok.Owner, tok.Name = "hanzo", "t1"
	tok.User, tok.Application, tok.Scope = "hanzo/alice", "hanzo/app", "openid"
	tok.AccessToken, tok.RefreshToken = "at-secret", "rt-secret"
	tok.AccessTokenHash, tok.RefreshTokenHash = "at-hash", "rt-hash"
	tok.CodeChallenge = "chal-secret"
	tok.Code, tok.UserCode = "auth-code-live", "USER-CODE-LIVE" // live, single-use, redeemable
	tok.SetId("hanzo/t1")
	if err := tok.CreateCtx(ctx); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	assertMasked := func(t *testing.T, got *schema.Token) {
		t.Helper()
		if got.AccessToken != "" || got.RefreshToken != "" {
			t.Fatalf("plaintext bearer leaked: access=%q refresh=%q", got.AccessToken, got.RefreshToken)
		}
		if got.AccessTokenHash != "" || got.RefreshTokenHash != "" {
			t.Fatalf("token hash leaked: access=%q refresh=%q", got.AccessTokenHash, got.RefreshTokenHash)
		}
		if got.CodeChallenge != "" {
			t.Fatalf("code challenge leaked: %q", got.CodeChallenge)
		}
		if got.Code != "" || got.UserCode != "" {
			t.Fatalf("live redeemable code leaked: code=%q userCode=%q", got.Code, got.UserCode)
		}
		if got.User != "hanzo/alice" || got.Application != "hanzo/app" || got.Scope != "openid" {
			t.Fatalf("non-secret metadata dropped: user=%q app=%q scope=%q", got.User, got.Application, got.Scope)
		}
	}

	res, err := getToken(db)(ctx, &tokenKey{Owner: "hanzo", Name: "t1"})
	if err != nil {
		t.Fatalf("getToken: %v", err)
	}
	assertMasked(t, res.Token)

	list, err := listTokens(db)(ctx, &listTokensIn{Owner: "hanzo"})
	if err != nil {
		t.Fatalf("listTokens: %v", err)
	}
	if len(list.Tokens) != 1 {
		t.Fatalf("listTokens returned %d rows, want 1", len(list.Tokens))
	}
	assertMasked(t, list.Tokens[0])
}

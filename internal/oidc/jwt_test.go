// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// testKey is a small (fast) RSA key — fine for tests; production uses the Cert.
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	// A fixed 2048-bit key generated once would be faster, but generating keeps
	// the test self-contained. 2048 is the JWKS minimum.
	k, err := rsaGenTest()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSign_RoundTripAndClaims(t *testing.T) {
	key := testKey(t)
	s := NewRSASigner(key, "cert-hanzo", "https://iam.hanzo.ai")
	now := time.Unix(1_800_000_000, 0)
	app := testApp()

	tokenStr, err := s.Sign(app, Identity{Id: "hanzo/alice", Email: "alice@hanzo.ai", Name: "alice"}, "openid profile", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with the public key + assert every claim.
	var claims Claims
	parsed, err := jwt.ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) }))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}
	if kid, _ := parsed.Header["kid"].(string); kid != "cert-hanzo" {
		t.Fatalf("kid = %q, want cert-hanzo", kid)
	}
	if claims.Issuer != "https://iam.hanzo.ai" {
		t.Fatalf("iss = %q", claims.Issuer)
	}
	if claims.Subject != "hanzo/alice" {
		t.Fatalf("sub = %q", claims.Subject)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "hanzo-console" {
		t.Fatalf("aud = %v, want [hanzo-console]", claims.Audience)
	}
	if claims.Owner != "hanzo" {
		t.Fatalf("owner = %q, want hanzo", claims.Owner)
	}
	if claims.Scope != "openid profile" || claims.Email != "alice@hanzo.ai" {
		t.Fatalf("scope/email wrong: %q / %q", claims.Scope, claims.Email)
	}
	if claims.ID == "" {
		t.Fatal("jti empty — every token must be uniquely identifiable")
	}
}

func TestSign_ExpiredTokenRejected(t *testing.T) {
	key := testKey(t)
	s := NewRSASigner(key, "cert-hanzo", "https://iam.hanzo.ai")
	now := time.Unix(1_800_000_000, 0)
	tokenStr, err := s.Sign(testApp(), Identity{Id: "u"}, "openid", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	// Validate well after expiry.
	var claims Claims
	_, err = jwt.ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(2 * time.Minute) }))
	if err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestSign_WrongKeyRejected(t *testing.T) {
	s := NewRSASigner(testKey(t), "cert-hanzo", "https://iam.hanzo.ai")
	other := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	tokenStr, _ := s.Sign(testApp(), Identity{Id: "u"}, "openid", time.Hour, now)
	var claims Claims
	_, err := jwt.ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) { return &other.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err == nil {
		t.Fatal("token verified under the wrong key")
	}
}

func TestParseRSAPrivateKeyPEM_RejectsGarbage(t *testing.T) {
	if _, err := parseRSAPrivateKeyPEM("not a pem"); err == nil {
		t.Fatal("garbage PEM accepted")
	}
}

func TestNewRSASignerFromCert_PEMRoundTrip(t *testing.T) {
	key := testKey(t)
	pemText := rsaKeyToPEM(t, key)
	cert := &schema.Cert{PrivateKey: pemText}
	cert.Name = "cert-hanzo"
	s, err := NewRSASignerFromCert(cert, "https://iam.hanzo.ai")
	if err != nil {
		t.Fatalf("load from cert PEM: %v", err)
	}
	if s.Kid() != "cert-hanzo" || s.PublicKey() == nil {
		t.Fatal("signer from cert missing kid/public key")
	}
	// Sign+verify to prove the parsed key works.
	now := time.Unix(1_800_000_000, 0)
	str, err := s.Sign(testApp(), Identity{Id: "u"}, "openid", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	var claims Claims
	if _, err := jwt.ParseWithClaims(str, &claims, func(*jwt.Token) (any, error) { return s.PublicKey(), nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) })); err != nil {
		t.Fatalf("verify with cert-loaded key: %v", err)
	}
}

// TestSignNamesTheUsernameNeverTheDisplayName pins the claim the whole platform
// addresses a principal by.
//
// `hanzo auth login` files its credential under `owner`/`name` read straight off
// the minted token, so those two claims ARE the principal downstream believes it
// holds. A real login as account "z" minted `name: "Zach Kelling"` — the human's
// display name, a label with a space in it — and every surface downstream then
// named an account that does not exist. cloud's money path had already been bitten
// by the same reading: it addresses a wallet `<org>/<username>`, addressed
// `hanzo/Zach Kelling`, and 402'd every completion while the balance sat in
// `hanzo/z`.
//
// So: `name` is the username, `preferred_username` is the same username, and the
// display name is carried under its own claim where nothing resolves an account
// from it.
func TestSignNamesTheUsernameNeverTheDisplayName(t *testing.T) {
	s := NewRSASigner(testKey(t), "cert-hanzo", "https://iam.hanzo.ai")
	now := time.Unix(1_800_000_000, 0)
	z := Identity{Id: "hanzo/z", Email: "z@hanzo.ai", Name: "z", Display: "Zach Kelling"}

	// Both token shapes, from the one claim builder — an id_token that disagreed
	// with its access token would be the same defect wearing a different name.
	access, err := s.Sign(testApp(), z, "openid profile", time.Hour, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	idt, err := s.SignID(testApp(), z, "openid profile", "n-1", time.Hour, now)
	if err != nil {
		t.Fatalf("SignID: %v", err)
	}
	for _, tc := range []struct{ shape, token string }{{"access", access}, {"id", idt}} {
		var got Claims
		if _, _, err := jwt.NewParser().ParseUnverified(tc.token, &got); err != nil {
			t.Fatalf("%s: parse: %v", tc.shape, err)
		}
		if got.Name != "z" {
			t.Fatalf("%s token: name = %q; want the USERNAME %q — the CLI files credentials under owner/name", tc.shape, got.Name, "z")
		}
		if got.PreferredUsername != "z" {
			t.Fatalf("%s token: preferred_username = %q; want %q", tc.shape, got.PreferredUsername, "z")
		}
		if got.Display != "Zach Kelling" {
			t.Fatalf("%s token: displayName = %q; want the human name carried in its own claim", tc.shape, got.Display)
		}
		if got.Owner != "hanzo" {
			t.Fatalf("%s token: owner = %q; want the ORG %q", tc.shape, got.Owner, "hanzo")
		}
	}

	// A principal with no profile (a machine token, or a since-deleted user) omits
	// every profile claim rather than emitting it empty — omitempty is what keeps
	// one struct serving both token shapes.
	bare, err := s.Sign(testApp(), Identity{Id: "hanzo/app"}, "openid", time.Hour, now)
	if err != nil {
		t.Fatalf("Sign bare: %v", err)
	}
	for _, claim := range []string{"preferred_username", "displayName", `"name"`} {
		if strings.Contains(bare, claim) {
			t.Fatalf("a profile-less token must omit %s, not emit it empty", claim)
		}
	}
}

// TestBillingAccountForOnlyAdminsSpendThePool pins who may spend the org pool.
//
// account.Payer honours a signed billing_account above everything else; absent
// one, its shape rule makes the SIGNUP ORG special — a member of any other org
// spends the org pool, but a member of "hanzo" gets a PERSONAL wallet, because
// every self-signup lands there and keying them on the pool let a brand-new $0
// account read Hanzo's balance and sail through the gate.
//
// So the claim is what lets a real admin spend company credit without reopening
// that hole: admins and owners name the pool, a plain member names nothing.
func TestBillingAccountForOnlyAdminsSpendThePool(t *testing.T) {
	// The value is "org:<slug>", never a bare slug: account.Parse Cuts on ":" and
	// returns a ZERO Account without the kind prefix, which Payer then ignores in
	// favour of its shape rule — so a bare slug is minted, signed, stamped into
	// X-Billing-Account-Id, carried to the gate and dropped there, silently.
	for _, tc := range []struct {
		name string
		refs []schema.OrgRef
		want string
	}{
		// "org:<slug>" — the kind prefix is load-bearing: account.Parse returns a
		// ZERO Account without it, so a bare slug is silently ignored by Payer.
		{"owner spends the pool", []schema.OrgRef{{Org: "hanzo", Role: "owner"}}, "org:hanzo"},
		{"admin spends the pool", []schema.OrgRef{{Org: "hanzo", Role: "admin"}}, "org:hanzo"},
		{"plain member does not", []schema.OrgRef{{Org: "hanzo", Role: "member"}}, ""},
		{"no role does not", []schema.OrgRef{{Org: "hanzo"}}, ""},
		{"no membership at all", nil, ""},
		// A token minted for one tenant must never name another's ledger, however
		// privileged the caller is elsewhere.
		{"admin of ANOTHER org does not", []schema.OrgRef{{Org: "lux", Role: "admin"}}, ""},
		{"admin elsewhere, member here", []schema.OrgRef{{Org: "lux", Role: "owner"}, {Org: "hanzo", Role: "member"}}, ""},
		{"admin here, member elsewhere", []schema.OrgRef{{Org: "lux", Role: "member"}, {Org: "hanzo", Role: "admin"}}, "org:hanzo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &schema.User{Owner: "hanzo", Name: "someone"}
			if got := store.BillingAccount(u, tc.refs); got != tc.want {
				t.Fatalf("store.BillingAccount = %q; want %q", got, tc.want)
			}
		})
	}
}

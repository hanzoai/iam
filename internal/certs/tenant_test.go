// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package certs_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// An ORGANIZATION'S OWN CERT is created by IAM: the key pair is generated here, the
// private half goes to the host's Vault, and a caller never supplies or reads key material.

type vault struct {
	mu   sync.Mutex
	m    map[[2]string]string
	fail bool
}

func (v *vault) Put(_ context.Context, org, name, pem string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fail {
		return errors.New("vault down")
	}
	if _, ok := v.m[[2]string{org, name}]; ok {
		return keyring.ErrExists
	}
	v.m[[2]string{org, name}] = pem
	return nil
}

func (v *vault) Get(_ context.Context, org, name string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if p, ok := v.m[[2]string{org, name}]; ok {
		return p, nil
	}
	return "", keyring.ErrNoKey
}

func (v *vault) Delete(_ context.Context, org, name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.m, [2]string{org, name})
	return nil
}

func (v *vault) held(org, name string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.m[[2]string{org, name}]
	return ok
}

func (h *harness) send(t *testing.T, method, path, bearer string, body any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(out)
}

func tenantHarness(t *testing.T) (*harness, *vault) {
	t.Helper()
	h := newHarness(t)
	v := &vault{m: map[[2]string]string{}}
	keyring.UseVault(v)
	t.Cleanup(func() { keyring.UseVault(nil) })
	seedUser(t, h.db, "acme", "boss", true)
	seedUser(t, h.db, "acme", "alice", false)
	seedUser(t, h.db, "orgb", "boss", true)
	// A platform cert whose name a tenant's may not equal, and one with a mixed-case name.
	seedCertRow(t, h.db, &schema.Cert{Owner: "admin", Name: "Mixed-Kid", CryptoAlgorithm: "RS256"})
	return h, v
}

func TestTenantCert_WhoMayCreateAndWhatIsRefused(t *testing.T) {
	h, v := tenantHarness(t)
	long := strings.Repeat("a", 65)
	for _, tc := range []struct {
		name   string
		as     string
		body   map[string]any
		want   int
		stored bool // the Vault holds a key afterwards
	}{
		{"org admin creates its own", "acme/boss", map[string]any{"owner": "acme", "name": "acme-key"}, 200, true},
		{"SuperAdmin creates for an org", "admin/root", map[string]any{"owner": "acme", "name": "root-key"}, 200, true},
		{"a member is refused", "acme/alice", map[string]any{"owner": "acme", "name": "member-key"}, 403, false},
		{"another org's admin is refused", "orgb/boss", map[string]any{"owner": "acme", "name": "foreign-key"}, 403, false},
		{"a platform org holds no tenant cert", "hanzo/boss", map[string]any{"owner": "hanzo", "name": "hanzo-key"}, 400, false},
		{"nor does the reserved admin org", "admin/root", map[string]any{"owner": "admin", "name": "admin-key"}, 400, false},
		{"a platform kid is taken", "acme/boss", map[string]any{"owner": "acme", "name": "cert-hanzo"}, 409, false},
		{"folding case", "acme/boss", map[string]any{"owner": "acme", "name": "mixed-kid"}, 409, false},
		{"uppercase is no kid", "acme/boss", map[string]any{"owner": "acme", "name": "Acme-Key"}, 400, false},
		{"a traversal is no kid", "acme/boss", map[string]any{"owner": "acme", "name": "a..b"}, 400, false},
		{"too long", "acme/boss", map[string]any{"owner": "acme", "name": long}, 400, false},
		{"supplied certificate", "acme/boss", map[string]any{"owner": "acme", "name": "mine", "certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}, 400, false},
		{"supplied secret", "acme/boss", map[string]any{"owner": "acme", "name": "mine2", "accessSecret": "s"}, 400, false},
		{"another algorithm", "acme/boss", map[string]any{"owner": "acme", "name": "es-key", "cryptoAlgorithm": "ES256"}, 400, false},
		{"too long a life", "acme/boss", map[string]any{"owner": "acme", "name": "old-key", "expireInYears": 21}, 400, false},
	} {
		body := tc.body
		body["scope"] = schema.CertTenant
		st, out := h.send(t, "POST", "/v1/iam/certs", h.token(t, tc.as), body)
		if st != tc.want {
			t.Errorf("%s: status %d, want %d: %s", tc.name, st, tc.want, out)
		}
		owner, _ := body["owner"].(string)
		name, _ := body["name"].(string)
		if got := v.held(owner, name); got != tc.stored {
			t.Errorf("%s: vault holds a key = %v, want %v", tc.name, got, tc.stored)
		}
		if !tc.stored {
			if _, err := orm.Get[schema.Cert](h.db, owner+"/"+name); err == nil && tc.want != 409 {
				t.Errorf("%s: a refused create left a row", tc.name)
			}
		}
	}
	// A second create of the same name is a conflict and does not replace the key.
	st, _ := h.send(t, "POST", "/v1/iam/certs", h.token(t, "acme/boss"), map[string]any{"owner": "acme", "name": "acme-key", "scope": schema.CertTenant})
	if st != 409 {
		t.Errorf("a repeat create: status %d, want 409", st)
	}
}

func TestTenantCert_NoVaultRefusesAndAVaultFailureLeavesNoRow(t *testing.T) {
	h, v := tenantHarness(t)
	boss := h.token(t, "acme/boss")
	body := map[string]any{"owner": "acme", "name": "k1", "scope": schema.CertTenant}

	v.fail = true
	if st, _ := h.send(t, "POST", "/v1/iam/certs", boss, body); st != 502 {
		t.Errorf("a failing vault: status %d, want 502", st)
	}
	if _, err := orm.Get[schema.Cert](h.db, "acme/k1"); err == nil {
		t.Error("a vault failure left a cert row with no key")
	}
	v.fail = false

	keyring.UseVault(nil)
	if st, out := h.send(t, "POST", "/v1/iam/certs", boss, body); st != 503 || !strings.Contains(out, "no tenant key vault") {
		t.Errorf("no vault: status %d: %s", st, out)
	}
	if _, err := orm.Get[schema.Cert](h.db, "acme/k1"); err == nil {
		t.Error("an unavailable vault left a cert row")
	}
}

// KEY MATERIAL NEVER LEAVES. The vault holds a private key; the row holds the public
// certificate of the same key; no response of the certs surface carries the private half.
func TestTenantCert_KeyNeverInAResponseAndRowHoldsThePublicHalf(t *testing.T) {
	h, v := tenantHarness(t)
	boss := h.token(t, "acme/boss")
	st, created := h.send(t, "POST", "/v1/iam/certs", boss, map[string]any{"owner": "acme", "name": "acme-key", "displayName": "Acme", "scope": schema.CertTenant})
	if st != 200 {
		t.Fatalf("create: %d %s", st, created)
	}
	priv, err := v.Get(context.Background(), "acme", "acme-key")
	if err != nil || !strings.Contains(priv, "PRIVATE KEY") {
		t.Fatalf("the vault holds no key: %v", err)
	}
	var row schema.Cert
	if err := json.Unmarshal([]byte(created), &row); err != nil {
		t.Fatal(err)
	}
	if row.Scope != schema.CertTenant || row.Owner != "acme" || row.CryptoAlgorithm != "RS256" || row.BitSize != 2048 || row.Type != "x509" {
		t.Fatalf("row = %+v", row)
	}
	// The certificate on the row is the public half of the vault's key.
	block, _ := pem.Decode([]byte(row.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode([]byte(priv))
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.PublicKey.(*rsa.PublicKey).N.Cmp(key.N) != 0 {
		t.Fatal("the row's certificate is not the vault key's public half")
	}
	// No surface serves the private half, or any private parameter of it.
	secrets := []string{priv, "PRIVATE KEY", base64Std(key.D.Bytes()), base64Std(key.Primes[0].Bytes()), `"privateKey"`}
	_, got := h.send(t, "GET", "/v1/iam/certs/acme/acme-key", boss, nil)
	_, list := h.send(t, "GET", "/v1/iam/certs?owner=acme", boss, nil)
	root := h.token(t, "admin/root")
	_, all := h.send(t, "GET", "/v1/iam/certs", root, nil)
	for name, out := range map[string]string{"create": created, "get": got, "list": list, "list-all": all} {
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s response carries key material (%.20q)", name, s)
			}
		}
	}
}

func base64Std(b []byte) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// a prefix long enough to identify the value without the whole key
	var out []byte
	for i := 0; i+2 < len(b) && len(out) < 24; i += 3 {
		n := uint(b[i])<<16 | uint(b[i+1])<<8 | uint(b[i+2])
		out = append(out, a[n>>18&63], a[n>>12&63], a[n>>6&63], a[n&63])
	}
	return string(out)
}

// A tenant cert stays what it was made: a PUT changes its display name and nothing
// else, a plain cert cannot become one, and deleting it forgets its key.
func TestTenantCert_UpdateIsMetadataOnlyAndDeleteForgetsTheKey(t *testing.T) {
	h, v := tenantHarness(t)
	boss := h.token(t, "acme/boss")
	_, created := h.send(t, "POST", "/v1/iam/certs", boss, map[string]any{"owner": "acme", "name": "acme-key", "scope": schema.CertTenant})
	var before schema.Cert
	_ = json.Unmarshal([]byte(created), &before)

	st, out := h.send(t, "PUT", "/v1/iam/certs/acme/acme-key", boss, map[string]any{
		"owner": "acme", "name": "acme-key", "displayName": "Renamed", "scope": "JWT",
		"certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "cryptoAlgorithm": "ES256", "expireInYears": 99,
	})
	if st != 200 {
		t.Fatalf("update: %d %s", st, out)
	}
	var after schema.Cert
	_ = json.Unmarshal([]byte(out), &after)
	if after.DisplayName != "Renamed" || after.Scope != schema.CertTenant || after.Certificate != before.Certificate ||
		after.CryptoAlgorithm != "RS256" || after.ExpireInYears != before.ExpireInYears {
		t.Fatalf("a tenant cert changed beyond its display name: %+v", after)
	}

	// A plain cert of the org cannot be turned into a tenant cert.
	seedCertRow(t, h.db, &schema.Cert{Owner: "acme", Name: "plain", CryptoAlgorithm: "RS256"})
	if st, _ := h.send(t, "PUT", "/v1/iam/certs/acme/plain", boss, map[string]any{"owner": "acme", "name": "plain", "scope": schema.CertTenant}); st != 400 {
		t.Fatalf("a plain cert became a tenant cert: status %d", st)
	}

	if st, _ := h.send(t, "DELETE", "/v1/iam/certs/acme/acme-key", boss, nil); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if v.held("acme", "acme-key") {
		t.Fatal("the vault still holds the key of a deleted cert")
	}
}

// An ordinary cert is created exactly as before: scope decides, and nothing is generated.
func TestTenantCert_PlainCertsAreUnchanged(t *testing.T) {
	h, v := tenantHarness(t)
	st, out := h.send(t, "POST", "/v1/iam/certs", h.token(t, "acme/boss"), map[string]any{"owner": "acme", "name": "Plain-Cert", "cryptoAlgorithm": "RS256", "scope": "JWT"})
	if st != 200 {
		t.Fatalf("plain create: %d %s", st, out)
	}
	if v.held("acme", "Plain-Cert") {
		t.Fatal("an ordinary cert was given a vault key")
	}
}

// A TENANT TOKEN IS NO PLATFORM CREDENTIAL. A person of the org signs in to the org's
// application and holds a token signed by the org's own cert under the org's own
// issuer; the Guard, which every platform-authority route sits behind, refuses it —
// while the same person's platform-signed token is answered.
func TestTenantCert_ATenantTokenIsRefusedAtThePlatformGuard(t *testing.T) {
	h, v := tenantHarness(t)
	boss := h.token(t, "acme/boss")
	if st, out := h.send(t, "POST", "/v1/iam/certs", boss, map[string]any{"owner": "acme", "name": "acme-key", "scope": schema.CertTenant}); st != 200 {
		t.Fatalf("create: %d %s", st, out)
	}
	priv, _ := v.Get(context.Background(), "acme", "acme-key")
	block, _ := pem.Decode([]byte(priv))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	claims := func(iss string) jwt.MapClaims {
		return jwt.MapClaims{
			"tokenType": "access-token", "iss": iss, "aud": "acme-portal", "sub": "acme/boss", "owner": "acme",
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
	}
	sign := func(iss, kid string, k *rsa.PrivateKey) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims(iss))
		tok.Header["kid"] = kid
		s, err := tok.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for name, tok := range map[string]string{
		"the org's cert and issuer":           sign("https://hanzo.id/acme", "acme-key", key),
		"the org's cert, a platform issuer":   sign("https://hanzo.id", "acme-key", key),
		"the org's cert under a platform kid": sign("https://hanzo.id", signingKid, key),
	} {
		if st, _ := h.send(t, "GET", "/v1/iam/certs?owner=acme", tok, nil); st != 401 {
			t.Errorf("%s: the platform Guard answered %d, want 401", name, st)
		}
	}
	// The control: the platform's own token for the same person is answered.
	if st, out := h.send(t, "GET", "/v1/iam/certs?owner=acme", h.token(t, "acme/boss"), nil); st != 200 {
		t.Fatalf("control: %d %s", st, out)
	}
}

// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package wallet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	luxcrypto "github.com/luxfi/crypto"
	wc "github.com/luxwallet/connect/go/walletconnect"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/oidc"
	"github.com/hanzoai/iam2/internal/schema"
)

// HTTP-level harness: every test drives the REAL mounted router behind the REAL
// authz Guard, so it exercises the wire contract a wallet client sees — the
// envelope, the reachability, the store effects.

const (
	// key is a fixed secp256k1 private key, so the golden vector below is
	// reproducible rather than regenerated per run.
	key = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	// addr is the lowercase EIP-191 address `key` recovers to.
	addr = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
	// host is the brand login host every request arrives on.
	host = "hanzo.id"
)

func tctx() context.Context { return context.Background() }

func openTestDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds() // force the schema init() (kind registration)
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "wallet.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newServer mounts the wallet surface exactly as routes.Route does: on the
// pre-authentication PUBLIC group (a root, empty-prefix router) registered
// BEFORE the Guard, so a matched route terminates the middleware walk and the
// Guard never runs on it. The Guard is still installed, so "anonymous
// reachability" is proved against the real fail-closed default, not around it.
func newServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	db := openTestDB(t)
	app := zip.New(zip.Config{AppName: "iam2-wallet-test", DisableStartupMessage: true})
	Route(app.Group(""), db)
	app.Use(authz.Guard(db))
	app.Authorize(authz.Authorize)
	return app, db
}

// opts configures a seeded application + its organization.
type opts struct {
	name   string
	org    string
	signup bool
	secret string // "" → public (PKCE) client
}

// seed creates the organization and application a wallet login routes through.
func seed(t *testing.T, db orm.DB, o opts) *schema.Application {
	t.Helper()
	if o.name == "" {
		o.name = "hanzo-cloud"
	}
	if o.org == "" {
		o.org = "hanzo"
	}
	org := orm.New[schema.Organization](db)
	org.Owner = "admin"
	org.Name = o.org
	org.DefaultAvatar = "https://cdn.hanzo.ai/avatar.png"
	org.SetId("admin/" + o.org)
	if err := org.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	a := orm.New[schema.Application](db)
	a.Owner = "admin"
	a.Name = o.name
	a.ClientId = o.name
	a.ClientSecret = o.secret
	a.Organization = o.org
	a.EnableSignUp = o.signup
	a.SetId("admin/" + o.name)
	if err := a.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	return a
}

// --- HTTP ---

// do drives one request through the mounted router and returns the HTTP status
// and the decoded envelope. Both matter: the status proves an error still rides
// a 200, the envelope proves what the client reads.
func do(t *testing.T, app *zip.App, req *http.Request) (int, map[string]any) {
	t.Helper()
	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %q (status %d): %v", string(raw), resp.StatusCode, err)
	}
	return resp.StatusCode, m
}

// get issues an anonymous GET against the brand host.
func get(t *testing.T, app *zip.App, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = host
	return do(t, app, req)
}

// post issues a JSON POST against the brand host. Extra headers (Origin,
// Authorization, a different Host) ride in hdr.
func post(t *testing.T, app *zip.App, path string, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	return do(t, app, req)
}

// --- the wallet client ---

// mint drives GET /v1/iam/web3/nonce and returns the challenge the wallet signs.
func mintFor(t *testing.T, app *zip.App, chain string) wc.LoginChallenge {
	t.Helper()
	_, m := get(t, app, PathNonce+"?chain="+chain+"&address="+addr)
	if m["status"] != "ok" {
		t.Fatalf("nonce: %v", m)
	}
	d, ok := m["data"].(map[string]any)
	if !ok {
		t.Fatalf("nonce data: %v", m["data"])
	}
	str := func(k string) string { s, _ := d[k].(string); return s }
	statement, expire, version := str("statement"), str("expirationTime"), str("version")
	return wc.LoginChallenge{
		Domain:         str("domain"),
		URI:            str("uri"),
		Statement:      &statement,
		Nonce:          str("nonce"),
		IssuedAt:       str("issuedAt"),
		ExpirationTime: &expire,
		Version:        &version,
	}
}

// signer is a wallet: a fixed secp256k1 key and the address it recovers to.
func signer(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := luxcrypto.HexToECDSA(key)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return k
}

// signWith renders the canonical CAIP-122 message for ch and signs it EIP-191,
// exactly as a browser wallet's personal_sign does. address is what goes on the
// message's signer line — a caller may pass a case/whitespace variant of the
// real address to probe canonicalization.
func signWith(t *testing.T, k *ecdsa.PrivateKey, ch wc.LoginChallenge, chain wc.Chain, address string) (message, signature string) {
	t.Helper()
	msg, err := wc.BuildSiwxMessage(wc.BuildParams{Challenge: ch, Address: address, Chain: chain})
	if err != nil {
		t.Fatalf("build message: %v", err)
	}
	sig, err := luxcrypto.Sign(wc.EIP191Digest(msg), k)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig[64] += 27 // wallets emit v as 27/28
	return msg, "0x" + hexOf(sig)
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// body builds a verify request for a signed message.
func body(app *schema.Application, chain wc.Chain, address, message, signature string) map[string]any {
	return map[string]any{
		"application": app.Name,
		"chain":       string(chain),
		"scheme":      string(wc.SchemeSecp256k1EIP191),
		"address":     address,
		"message":     message,
		"signature":   signature,
	}
}

// signIn runs the whole flow: mint a nonce, sign it, verify. The happy path.
func signIn(t *testing.T, app *zip.App, a *schema.Application) (int, map[string]any) {
	t.Helper()
	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	return post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), nil)
}

// --- store assertions ---

func users(t *testing.T, db orm.DB) []*schema.User {
	t.Helper()
	all, err := orm.TypedQuery[schema.User](db).GetAll(tctx())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	return all
}

func wallets(t *testing.T, db orm.DB) []*schema.Wallet {
	t.Helper()
	all, err := orm.TypedQuery[schema.Wallet](db).GetAll(tctx())
	if err != nil {
		t.Fatalf("list wallets: %v", err)
	}
	return all
}

func challenges(t *testing.T, db orm.DB) []*schema.Challenge {
	t.Helper()
	all, err := orm.TypedQuery[schema.Challenge](db).GetAll(tctx())
	if err != nil {
		t.Fatalf("list challenges: %v", err)
	}
	return all
}

// --- a real bearer, for the one branch that honors a session ---

// bearer seeds a signing cert + a user, and returns a token the authz Guard's
// verifier accepts for that user.
func bearer(t *testing.T, db orm.DB, a *schema.Application, org, name string) (*schema.User, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	c := orm.New[schema.Cert](db)
	c.Owner = "admin" // a reserved signing-cert owner — the trust boundary
	c.Name = "cert-wallet"
	c.CryptoAlgorithm = "RS256"
	c.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
	c.SetId("admin/cert-wallet")
	if err := c.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	u := orm.New[schema.User](db)
	u.Owner = org
	u.Name = name
	u.Type = "normal-user"
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	tok, err := oidc.NewRSASigner(k, "cert-wallet", "https://"+host).
		Sign(a, org+"/"+name, "", "", "openid", time.Hour, time.Now())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return u, tok
}

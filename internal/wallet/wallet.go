// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package wallet is native multi-chain wallet sign-in for IAM (HIP-0111):
// keyless CAIP-122 challenge/response over github.com/luxwallet/connect/go —
// the SAME VerifyProof the TypeScript SDK runs, so Go and TS verify identically.
//
//	GET  /v1/iam/web3/nonce   -> mint a single-use CAIP-122 challenge
//	POST /v1/iam/web3/verify  -> verify a signed proof; THIS is the login
//
// Both are anonymous-reachable by construction: they precede any token, so
// they are registered on the public route group (before the Guard). Neither reads tenant data nor
// takes a state-changing action on a caller's behalf — the nonce writes only its
// own challenge row, and verify acts solely on a cryptographically-verified
// address.
//
// HTTP shell only. The auth logic (burn, verify, resolve) lives in verify.go so
// it stays unit-testable and decomplected from the transport.
package wallet

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	wc "github.com/luxwallet/connect/go/walletconnect"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The canonical wallet sign-in endpoints.
const (
	PathNonce  = "/v1/iam/web3/nonce"
	PathVerify = "/v1/iam/web3/verify"
)

// Route registers the wallet sign-in surface on the PUBLIC route group (before
// the authz Guard): a wallet holder has no token until this flow gives them one,
// so membership in the public group is what makes the two endpoints reachable
// without a bearer.
func Route(r zip.Router, db orm.DB) {
	r.Get(PathNonce, nonce(db))
	r.Post(PathVerify, check(db))
}

// challenge is the LoginChallenge the client feeds to connector.signLogin().
// The field names mirror walletconnect.LoginChallenge so the JS passes it
// through unchanged, and the set is exact: renaming or dropping one desyncs the
// message the wallet SIGNS from the one the server PARSES, which reads as a
// universal bad-signature.
type challenge struct {
	Domain         string `json:"domain"`
	URI            string `json:"uri"`
	Statement      string `json:"statement,omitempty"`
	Nonce          string `json:"nonce"`
	IssuedAt       string `json:"issuedAt"`
	ExpirationTime string `json:"expirationTime,omitempty"`
	Version        string `json:"version"`
}

// nonce starts a wallet sign-in: it returns a one-time challenge for the wallet
// to sign. The challenge is good once and is tied to the site that asked for it,
// so a signature collected elsewhere cannot be replayed here.
func nonce(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		chain := wc.Chain(trim(c.Query("chain")))
		if !supported(chain) {
			return httpx.Err(c, "web3: unsupported chain: "+string(chain))
		}
		// The domain is the brand login host the request arrived on, read through
		// the header-immune c.Host() (zip has no trusted-proxy knob, so a client
		// X-Forwarded-Host is ignored) — NEVER client-supplied. The whole
		// anti-phishing binding the wallet signs (the EIP-4361/CAIP-122 `domain`)
		// rides on this, so it MUST be the true routed brand host, never a
		// spoofable header. It is the SAME accessor the OIDC issuer resolver uses.
		domain := trim(c.Host())
		if domain == "" {
			return httpx.Err(c, "web3: empty domain")
		}

		n, err := random()
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		now := time.Now().UTC()
		expire := now.Add(ttl)
		if err := mint(c.Context(), db, &schema.Challenge{
			Owner:       owner,
			Name:        n,
			Chain:       string(chain),
			Address:     trim(c.Query("address")),
			Domain:      domain,
			CreatedTime: stamp(now),
			ExpireTime:  stamp(expire),
		}); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, challenge{
			Domain:         domain,
			URI:            "https://" + domain + "/login",
			Statement:      statement,
			Nonce:          n,
			IssuedAt:       stamp(now),
			ExpirationTime: stamp(expire),
			Version:        "1",
		})
	}
}

// proof is the POST body: a walletconnect SignedProof plus the routing the shell
// resolves and the authorize params the mint passes through.
type proof struct {
	Organization string         `json:"organization"`
	Application  string         `json:"application"`
	Method       string         `json:"method"` // "signup" (default) | "login"
	Chain        string         `json:"chain"`
	Scheme       string         `json:"scheme"`
	Address      string         `json:"address"`
	PublicKey    string         `json:"publicKey,omitempty"`
	Message      string         `json:"message"`
	Signature    string         `json:"signature"`
	Extra        map[string]any `json:"extra,omitempty"`

	// Authorize passthrough. Type defaults to "login" (the shape the login page
	// expects); Type="code" + the rest drives the PKCE authorize flow.
	Type                string `json:"type"`
	ClientId            string `json:"clientId"`
	RedirectUri         string `json:"redirectUri"`
	State               string `json:"state"`
	Scope               string `json:"scope"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
}

// Field bounds, enforced before any per-chain parser reaches the input. A real
// proof's message/signature/key are a few hundred bytes; a multi-MB field is the
// parser-bomb vector (a deeply-nested Cardano COSE blob can fatally overflow the
// Go stack — uncatchable by recover, taking the IdP down). The SDK carries its
// own looser caps; these are defense in depth, rejecting early and cheaply.
const (
	maxField   = 8 * 1024 // message / signature
	maxKey     = 1024     // publicKey
	maxAddress = 256
)

// check completes a wallet sign-in: it verifies the signed challenge and, if it
// holds, signs the wallet's owner in.
//
// This IS the login — it answers exactly as a password sign-in does, so the rest
// of your flow does not branch on how somebody arrived.
func check(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f proof
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		if len(f.Signature) > maxField || len(f.Message) > maxField ||
			len(f.PublicKey) > maxKey || len(f.Address) > maxAddress {
			return httpx.Err(c, "web3: oversized proof field")
		}
		chain := wc.Chain(trim(f.Chain))
		if !supported(chain) {
			return httpx.Err(c, "web3: unsupported chain: "+string(chain))
		}

		ctx := c.Context()
		app, err := oidc.ResolveApp(ctx, db, f.ClientId, f.Application)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if app == nil {
			return httpx.Err(c, "application not found")
		}
		org, err := store.GetOrganizationByName(ctx, db, app.Organization)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if org == nil {
			return httpx.Err(c, "web3: organization not found")
		}

		user, err := verify(ctx, db, login{
			// Same header-immune c.Host() as the mint: verify re-derives the domain
			// from the true routed brand host and re-checks it against the burned
			// challenge, so a spoofed X-Forwarded-Host can neither steer the binding
			// nor slip a cross-host redemption past the domain check.
			Domain: trim(c.Host()),
			Proof: wc.Proof{
				Chain:     chain,
				Scheme:    wc.SignatureScheme(f.Scheme),
				Address:   f.Address,
				PublicKey: f.PublicKey,
				Message:   f.Message,
				Signature: f.Signature,
				Extra:     f.Extra,
			},
			Method:  f.Method,
			App:     app,
			Org:     org,
			Session: session(c, db),
		}, time.Now().UTC())
		if err != nil {
			return httpx.Err(c, err.Error())
		}

		// The multi-factor gate belongs HERE — after the wallet proves the
		// identity, before any session or code is minted. v1 runs checkMfaEnable
		// at exactly this point with an empty verificationType (wallet login has
		// no SMS/email pre-step). iam has no MFA gate yet; this is the ONE call
		// site it binds into, so wallet login never becomes a silent MFA bypass.
		if factor(user, org) {
			return httpx.Err(c, "web3: multi-factor authentication is required")
		}

		data, err := oidc.MintFor(ctx, db, app, user.Owner+"/"+user.Name, oidc.Mint{
			Type:                f.Type,
			RedirectUri:         f.RedirectUri,
			State:               f.State,
			Scope:               f.Scope,
			Nonce:               f.Nonce,
			CodeChallenge:       f.CodeChallenge,
			CodeChallengeMethod: f.CodeChallengeMethod,
		})
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, data)
	}
}

// factor reports whether user must clear a second factor before a session is
// minted. iam has no MFA gate yet, so it always reports "not required" — the
// call site above exists so the gate lands in one place rather than being
// rediscovered, and so its absence is visible rather than silent.
func factor(_ *schema.User, _ *schema.Organization) bool { return false }

// session resolves the authenticated caller, but ONLY on a same-site request.
//
// This is the sole branch of the flow carrying ambient authority (the caller's
// bearer), and the only one that attaches a verified wallet to an EXISTING
// identity. A cross-site forged POST must not be able to attach an attacker's
// wallet to a victim's account, so a cross-site caller is treated as anonymous
// and falls through to the login/signup branches, which have no ambient
// authority to abuse.
func session(c *zip.Ctx, db orm.DB) *schema.User {
	if !same(c) {
		return nil
	}
	p := authz.Optional(c, db)
	if p == nil || p.User == "" {
		return nil // anonymous, unverifiable, or a machine token with no identity
	}
	user, err := store.GetUserByName(c.Context(), db, p.Org, p.User)
	if err != nil {
		return nil
	}
	return user
}

// same reports whether the request is same-site: the Origin (else Referer) host
// equals the brand host the request arrived on.
//
// A request carrying NEITHER header is same-site: there is no browser
// cross-site context to abuse. A CSRF attack needs a browser, and browsers
// attach Origin to a cross-site POST; a native or server-side client sends
// neither, and refusing those would break wallet linking from them for no
// security gain. A malformed Origin/Referer, or one naming another host, is
// cross-site. Hosts compare case-insensitively (DNS is).
//
// The comparison target is the header-immune c.Host(), NOT a client header: an
// attacker who could also spoof X-Forwarded-Host to equal their forged Origin
// would otherwise pass this check cross-site. c.Host() is the true routed brand
// host, so a forged Origin can never match it.
func same(c *zip.Ctx) bool {
	src := c.Header("Origin")
	if src == "" {
		src = c.Header("Referer")
	}
	if src == "" {
		return true
	}
	if u, err := url.Parse(src); err == nil && u.Host != "" {
		return strings.EqualFold(u.Host, trim(c.Host()))
	}
	return false // malformed → fail closed (treat as cross-site)
}

// random returns a crypto-random 32-character nonce (128 bits, far above the
// CAIP-122 minimum of 8). It MUST be random, never time-derived: a per-second id
// both COLLIDES on the (owner, name) key when two logins land in the same second
// and is guessable, weakening the replay guard the single-use burn provides.
func random() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// trim is the one input-trim used across the shell.
func trim(s string) string { return strings.TrimSpace(s) }

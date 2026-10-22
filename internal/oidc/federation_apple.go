// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Sign in with Apple is OIDC with three differences the generic dialect cannot
// express: the client secret is an ES256 JWT the relying party signs with its own
// key, minted per exchange; the endpoints are fixed rather than discovered; and
// asking for a name or an address requires response_mode=form_post, so the browser
// returns by a cross-site POST instead of a redirect.
//
// The Provider row keeps the v1 field mapping, so a migrated row works unchanged:
//
//	ClientId       Services ID — the OAuth client_id, and the secret's sub
//	ClientSecret   Team ID — the secret's iss
//	ClientId2      Key ID — the secret's kid
//	ClientSecret2  the .p8 private key (PKCS#8 PEM, or its base64 body)
//
// The two secret fields are the ones Provider.Mask and loginView blank.

// appleIssuer is Apple's issuer; its endpoints sit at fixed paths under it.
const appleIssuer = "https://appleid.apple.com"

// appleSecretTTL is the client secret's life. Apple accepts up to six months; one
// is minted per exchange, so it need only outlive the request.
const appleSecretTTL = 5 * time.Minute

// appleOrigin is the issuer the provider federates with: Apple's, unless the row
// names another in IssuerUrl (a test's mock). The endpoint paths never move.
func appleOrigin(p *schema.Provider) string {
	return strings.TrimRight(strings.TrimSpace(firstNonEmpty(p.IssuerUrl, appleIssuer)), "/")
}

// posts reports whether the provider returns to the callback by form_post rather
// than a redirect. Apple is the one dialect that does.
func posts(p *schema.Provider) bool { return idpKind(p) == "apple" }

// appleKey answers whether the provider can mint a client secret: a Team ID, a
// Key ID, and a .p8 that parses as a P-256 PKCS#8 key, as PEM or as its bare
// base64 body (the form that survives a JSON document or an environment variable
// without its line breaks).
func appleKey(p *schema.Provider) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(p.ClientSecret) == "" || strings.TrimSpace(p.ClientId2) == "" {
		return nil, errors.New("federation: Apple provider has no team id or key id")
	}
	raw := strings.TrimSpace(p.ClientSecret2)
	var der []byte
	if b, _ := pem.Decode([]byte(raw)); b != nil {
		der = b.Bytes
	} else {
		d, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(raw), ""))
		if err != nil || len(d) == 0 {
			return nil, errors.New("federation: Apple key is neither PEM nor base64")
		}
		der = d
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("federation: Apple key is not PKCS#8")
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("federation: Apple key is not a P-256 key")
	}
	return ec, nil
}

// appleSecret mints the client secret Apple's token endpoint takes: an ES256 JWT
// with kid = Key ID, iss = Team ID, sub = the Services ID, aud = the issuer, valid
// for appleSecretTTL from now. aud is a string, the form Apple documents.
func appleSecret(p *schema.Provider, issuer string, now time.Time) (string, error) {
	key, err := appleKey(p)
	if err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": strings.TrimSpace(p.ClientSecret),
		"sub": p.ClientId,
		"aud": issuer,
		"iat": now.Unix(),
		"exp": now.Add(appleSecretTTL).Unix(),
	})
	tok.Header["kid"] = strings.TrimSpace(p.ClientId2)
	return tok.SignedString(key)
}

// appleAuthorizeURL builds Apple's authorization request: the code flow with
// form_post (required once a scope is asked for), the app-or-default scope, our
// callback, the single-use state and the nonce the id_token must echo. Apple
// documents no PKCE for the web flow, so the secret JWT authenticates the exchange.
func appleAuthorizeURL(p *schema.Provider, st *schema.FederationState, callback string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("response_mode", "form_post")
	v.Set("client_id", p.ClientId)
	v.Set("redirect_uri", callback)
	v.Set("scope", providerScopes(p, "name email"))
	v.Set("state", st.Name)
	v.Set("nonce", st.IdpNonce)
	return joinQuery(appleOrigin(p)+"/auth/authorize", v)
}

// appleExchange redeems the code with a freshly minted secret, then VERIFIES the
// id_token — signature against Apple's JWKS, issuer, audience (== the Services
// ID), expiry and nonce. The subject and address come from that token; the
// address may be a private relay one, which Apple reports verified. user is the
// form field Apple posts on the first authorization only, and the name is all it
// supplies.
func appleExchange(ctx context.Context, p *schema.Provider, st *schema.FederationState, code, user, callback string, now time.Time) (federatedIdentity, error) {
	issuer := appleOrigin(p)
	secret, err := appleSecret(p, issuer, now)
	if err != nil {
		return federatedIdentity{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", callback)
	form.Set("client_id", p.ClientId)
	form.Set("client_secret", secret)

	var tr oidcTokenResponse
	if err := postFormJSON(ctx, issuer+"/auth/token", form, nil, &tr); err != nil {
		return federatedIdentity{}, err
	}
	if tr.IDToken == "" {
		return federatedIdentity{}, errors.New("federation: Apple token response carried no id_token")
	}
	claims, err := verifyIDToken(ctx, tr.IDToken, issuer+"/auth/keys", issuer, p.ClientId, st.IdpNonce, now)
	if err != nil {
		return federatedIdentity{}, err
	}
	return federatedIdentity{
		subject:       claims.Subject,
		email:         store.NormalizeEmail(claims.Email),
		emailVerified: truthy(claims.EmailVerified),
		displayName:   appleName(user),
	}, nil
}

// appleName reads the name out of Apple's `user` field,
// {"name":{"firstName":…,"lastName":…},"email":…}. The field is unsigned, so it
// supplies a display name and nothing else; an absent or unreadable one is "".
func appleName(user string) string {
	var u struct {
		Name struct {
			First string `json:"firstName"`
			Last  string `json:"lastName"`
		} `json:"name"`
	}
	if user == "" || json.Unmarshal([]byte(user), &u) != nil {
		return ""
	}
	return strings.TrimSpace(u.Name.First + " " + u.Name.Last)
}

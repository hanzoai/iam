// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Multi-chain wallet login for IAM, built on github.com/luxwallet/connect/go.
//
// HTTP shell only -- the auth logic (nonce burn, signature verify, user
// resolution) lives in object/web3_auth.go so it stays unit-testable and
// decomplected from beego. Replaces the unverified idp/metamask.go +
// idp/web3onboard.go path (which trusted a client-supplied address with NO
// signature check) with one canonical, fail-closed verify path that runs the
// SAME walletconnect.VerifyProof the TS SDK runs.
//
// HIP-0111: canonical paths under /v1/iam/... ONLY. Never /api/, never /oauth.
//   GET  /v1/iam/web3/nonce   -> mint + store a single-use CAIP-122 challenge
//   POST /v1/iam/web3/verify  -> verify a SignedProof, burn the nonce, log in

package controllers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hanzoai/iam/form"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"

	wc "github.com/luxwallet/connect/go/walletconnect"
)

// web3Domain is the RFC-4501 dnsauthority the wallet signs against. It MUST equal
// the brand login host (hanzo.id / lux.id / zoo.id / pars.id), not the API host,
// and MUST match what the frontend renders into the CAIP-122 message. Phishing
// protection rides entirely on this binding, so it is derived from the request
// host (getEffectiveHost), never taken from the client.
func (c *ApiController) web3Domain() string {
	return c.getEffectiveHost()
}

// Web3NonceResponse is the LoginChallenge the frontend feeds to
// connector.signLogin(). Field names mirror walletconnect.LoginChallenge / the TS
// LoginChallenge so the JS side passes it through unchanged.
type Web3NonceResponse struct {
	Domain         string `json:"domain"`
	URI            string `json:"uri"`
	Statement      string `json:"statement,omitempty"`
	Nonce          string `json:"nonce"`
	IssuedAt       string `json:"issuedAt"`
	ExpirationTime string `json:"expirationTime,omitempty"`
	Version        string `json:"version"`
	RequestID      string `json:"requestId,omitempty"`
}

// GetWeb3Nonce mints a single-use login nonce and returns the CAIP-122 challenge.
//
// Route: GET /v1/iam/web3/nonce?chain=<evm|solana|bitcoin|ton|xrp>&address=<addr>
//
// The (chain,address) are advisory here (they let us scope/rate-limit the nonce);
// the authoritative binding happens in VerifyProof against the SIGNED message.
func (c *ApiController) GetWeb3Nonce() {
	chain := wc.Chain(strings.TrimSpace(c.Ctx.Input.Query("chain")))
	address := strings.TrimSpace(c.Ctx.Input.Query("address"))

	if !object.IsSupportedWeb3Chain(chain) {
		c.ResponseError(fmt.Sprintf("web3: unsupported chain: %s", chain))
		return
	}

	_, challenge, err := object.MintWeb3Challenge(c.web3Domain(), chain, address)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	resp := &Web3NonceResponse{
		Domain:   challenge.Domain,
		URI:      challenge.URI,
		Nonce:    challenge.Nonce,
		IssuedAt: challenge.IssuedAt,
		Version:  "1",
	}
	if challenge.Statement != nil {
		resp.Statement = *challenge.Statement
	}
	if challenge.ExpirationTime != nil {
		resp.ExpirationTime = *challenge.ExpirationTime
	}
	if challenge.Version != nil {
		resp.Version = *challenge.Version
	}
	c.ResponseOk(resp)
}

// Web3VerifyForm is the POST body the frontend sends after the wallet signs. It
// is a walletconnect SignedProof plus the routing fields IAM needs to resolve the
// application/organization, pick signup vs login, and (for the OAuth code flow)
// carry the standard authorize params through to HandleLoggedIn.
type Web3VerifyForm struct {
	Organization string                 `json:"organization"`
	Application  string                 `json:"application"`
	Method       string                 `json:"method"` // "signup" (default) | "login"
	Chain        string                 `json:"chain"`
	Scheme       string                 `json:"scheme"`
	Address      string                 `json:"address"`
	PublicKey    string                 `json:"publicKey,omitempty"`
	Message      string                 `json:"message"`
	Signature    string                 `json:"signature"`
	Extra        map[string]interface{} `json:"extra,omitempty"`

	// OAuth passthrough. Type defaults to "login" (sets a session cookie, the
	// shape the login page expects). Set Type="code" + the rest for the
	// authorize redirect flow; HandleLoggedIn also reads these from the query
	// string, so either transport works.
	Type                string `json:"type"`
	ClientId            string `json:"clientId"`
	RedirectUri         string `json:"redirectUri"`
	State               string `json:"state"`
	Scope               string `json:"scope"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
}

// VerifyWeb3 verifies a multi-chain wallet login proof and signs the user in.
//
// Route: POST /v1/iam/web3/verify
//
// Thin shell: resolve application/organization/session, hand the proof to
// object.VerifyWalletLogin (which burns the nonce, runs walletconnect.VerifyProof,
// and resolves/provisions the user), then HandleLoggedIn -> the SAME success
// shape as Login().
func (c *ApiController) VerifyWeb3() {
	var f Web3VerifyForm
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &f); err != nil {
		c.ResponseError(err.Error())
		return
	}

	// DoS guard (defense-in-depth): bound every attacker-controlled field BEFORE
	// it reaches a per-chain parser. A real proof's signature/message/key are a
	// few hundred bytes; a multi-MB field is the CBOR/parser-bomb vector (e.g. a
	// deeply-nested Cardano COSE blob whose decode can fatally overflow the Go
	// stack — uncatchable by recover, taking down the IdP). Reject early, cheap.
	const (
		maxField   = 8 * 1024 // signature/message
		maxKey     = 1024     // publicKey
		maxAddress = 256      // address
	)
	if len(f.Signature) > maxField || len(f.Message) > maxField ||
		len(f.PublicKey) > maxKey || len(f.Address) > maxAddress {
		c.ResponseError("web3: oversized proof field")
		return
	}

	chain := wc.Chain(strings.TrimSpace(f.Chain))
	if !object.IsSupportedWeb3Chain(chain) {
		c.ResponseError(fmt.Sprintf("web3: unsupported chain: %s", chain))
		return
	}

	application, err := object.GetApplication(util.GetId("admin", f.Application))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError(c.T("auth:Failed to login in: application not found"))
		return
	}

	organization, err := object.GetOrganization(util.GetId("admin", application.Organization))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if organization == nil {
		c.ResponseError("web3: organization not found")
		return
	}

	// An authenticated caller is linking a new wallet to their existing
	// identity. getCurrentUser returns nil when anonymous.
	//
	// CSRF guard (account-takeover defense): the "link this wallet to my
	// session user" branch is the only part of this flow that carries ambient
	// authority (the session cookie). A cross-site forged POST must NOT be able
	// to attach an attacker's verified wallet to a victim's logged-in session.
	// So we only honor the session identity when the request is same-site:
	// Origin (or Referer) host must equal the brand host the request arrived on.
	// Anonymous login/signup branches are unaffected (no ambient authority to
	// abuse); a cross-site caller simply falls through to those.
	sessionUser := c.getCurrentUser()
	if sessionUser != nil && !c.isSameSiteRequest() {
		sessionUser = nil
	}

	user, err := object.VerifyWalletLogin(object.WalletLoginInput{
		Domain:       c.web3Domain(),
		Chain:        chain,
		Scheme:       f.Scheme,
		Address:      f.Address,
		PublicKey:    f.PublicKey,
		Message:      f.Message,
		Signature:    f.Signature,
		Extra:        f.Extra,
		Method:       f.Method,
		Application:  application,
		Organization: organization,
		SessionUser:  sessionUser,
	})
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// MFA gate (shared with the password/OAuth paths). Empty verificationType:
	// wallet login has no SMS/email pre-step.
	if checkMfaEnable(c, user, organization, "") {
		return
	}

	// Default to a session-cookie login (Type=="login"); pass through the OAuth
	// authorize params for the code flow. Same AuthForm the password Login
	// builds, so HandleLoggedIn returns the identical success shape.
	responseType := f.Type
	if responseType == "" {
		responseType = ResponseTypeLogin
	}
	authForm := &form.AuthForm{
		Type:                responseType,
		Organization:        application.Organization,
		Application:         application.Name,
		Provider:            "",
		ClientId:            f.ClientId,
		RedirectUri:         f.RedirectUri,
		State:               f.State,
		CodeChallenge:       f.CodeChallenge,
		CodeChallengeMethod: f.CodeChallengeMethod,
	}

	resp := c.HandleLoggedIn(application, user, authForm)
	c.Ctx.Input.SetParam("recordUserId", user.GetId())
	c.ResponseOk(resp)
}

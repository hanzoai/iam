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

// /v1/iam/whoami is the first production use of ZAP capability auth.
//
// Two endpoints land here:
//   - /v1/iam/whoami      — accepts either Authorization: Bearer <jwt> OR
//                           Authorization: ZAP <b64>, peer paths during
//                           the migration window
//   - /v1/iam/whoami/zap  — accepts ONLY Authorization: ZAP <b64>, exists
//                           for clean A/B testing of the cap path
//
// Both return a small principal description; the cap path additionally
// surfaces the cap kind, expiry, and the issuer hash so clients can
// observe-debug their cap chain.

package controllers

import (
	"net/http"

	"github.com/hanzoai/iam/capauth"
	"github.com/hanzoai/iam/object"
	"github.com/zap-proto/go/cap"
)

// whoamiResponse is the JSON body for /v1/iam/whoami.
//
// The dual shape (Principal vs Cap fields) is intentional: ZAP-authed
// requests fill the Cap block, JWT-authed requests fill only Principal.
// This lets callers tell which auth path served them without parsing the
// auth header back out, which matters during the migration window.
type whoamiResponse struct {
	// AuthScheme is "zap" or "bearer". Empty means unauthenticated.
	AuthScheme string `json:"authScheme"`

	// Principal is the user/service identifier. For Bearer it's owner/name;
	// for ZAP it's the hex-encoded holder pubkey hash.
	Principal string `json:"principal"`

	// Cap block is populated only on the ZAP path.
	Cap *whoamiCap `json:"cap,omitempty"`
}

type whoamiCap struct {
	Kind        uint32 `json:"kind"`
	HolderHex   string `json:"holderHex"`
	IssuerHex   string `json:"issuerHex"`
	IssuedAt    uint64 `json:"issuedAt"`
	ExpiresAt   uint64 `json:"expiresAt"`
	Permissions uint64 `json:"permissions"`
}

func (c *ApiController) writeWhoamiUnauthorized(scheme, errCode, desc string) {
	c.Ctx.Output.Header("WWW-Authenticate",
		scheme+` error="`+errCode+`", error_description="`+desc+`"`)
	c.Ctx.Output.SetStatus(http.StatusUnauthorized)
	c.Data["json"] = map[string]string{
		"error":             errCode,
		"error_description": desc,
	}
	c.ServeJSON()
}

// Whoami serves /v1/iam/whoami. Dispatches on Authorization scheme: ZAP path
// goes through the cap verifier; Bearer path keeps the legacy JWT
// session-lookup behavior; anything else is 401.
//
// @Title Whoami
// @Tag Account API
// @Description return the current principal under either ZAP cap or JWT bearer auth
// @Success 200 {object} controllers.whoamiResponse
// @router /whoami [get]
func (c *ApiController) Whoami() {
	if capauth.HasHeader(c.Ctx) {
		c.whoamiZAP()
		return
	}
	c.whoamiBearer()
}

// WhoamiZAP serves /v1/iam/whoami/zap — ZAP-only, no Bearer fallback. Used
// for clean A/B testing of the cap path with no chance of an accidental JWT
// match.
//
// @Title WhoamiZAP
// @Tag Account API
// @Description return the current principal under ZAP capability auth only
// @Success 200 {object} controllers.whoamiResponse
// @router /whoami/zap [get]
func (c *ApiController) WhoamiZAP() {
	if !capauth.HasHeader(c.Ctx) {
		c.writeWhoamiUnauthorized("ZAP", "invalid_token",
			"endpoint requires Authorization: ZAP <base64-cap>")
		return
	}
	c.whoamiZAP()
}

// whoamiZAP runs the cap verification path and writes the response.
func (c *ApiController) whoamiZAP() {
	if err := capauth.Verify(c.Ctx, cap.KindIAMSession); err != nil {
		// Map cap-package errors to RFC 6750–ish strings. The error code
		// space is intentionally small: invalid_token covers structural
		// problems, expired_token covers time, insufficient_scope covers
		// kind mismatch.
		errCode := "invalid_token"
		switch err {
		case cap.ErrExpired:
			errCode = "expired_token"
		case capauth.ErrWrongKind:
			errCode = "insufficient_scope"
		}
		c.writeWhoamiUnauthorized("ZAP", errCode, err.Error())
		return
	}
	// The verifier stashed holder + kind on the context for us.
	holderHex, _ := c.Ctx.Input.GetData(capauth.CtxKeyHolderHex).(string)
	kind, _ := c.Ctx.Input.GetData(capauth.CtxKeyKind).(uint32)
	cv, _ := c.Ctx.Input.GetData(capauth.CtxKeyCap).(cap.Cap)

	resp := whoamiResponse{
		AuthScheme: "zap",
		Principal:  holderHex,
		Cap: &whoamiCap{
			Kind:        kind,
			HolderHex:   holderHex,
			IssuerHex:   capauth.Hex32(cv.Issuer()),
			IssuedAt:    cv.IssuedAt(),
			ExpiresAt:   cv.ExpiresAt(),
			Permissions: cv.Permissions(),
		},
	}
	c.Data["json"] = resp
	c.ServeJSON()
}

// whoamiBearer runs the legacy JWT-bearer path. Mirrors GetUserinfo's session
// lookup but returns the whoamiResponse shape so clients see a single,
// predictable contract.
func (c *ApiController) whoamiBearer() {
	userId := c.GetSessionUsername()
	if userId == "" {
		c.writeWhoamiUnauthorized("Bearer", "invalid_token",
			"no session or valid bearer token")
		return
	}
	if object.IsAppUser(userId) {
		// App users (M2M) — preserve override-via-query semantics from
		// GetUserinfo so existing integrations don't break under whoami.
		if tmp := c.Ctx.Input.Query("userId"); tmp != "" {
			userId = tmp
		}
	}
	resp := whoamiResponse{
		AuthScheme: "bearer",
		Principal:  userId,
	}
	c.Data["json"] = resp
	c.ServeJSON()
}

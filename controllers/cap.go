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

// cap.go — /v1/iam/cap/* endpoints: issue, issuer-keys, revoke.
//
// This is the IAM HTTP edge for the ZAP capability surface. Three routes:
//
//   POST /v1/iam/cap/issue        — mint a root cap for an authenticated user
//                                   or service account. Auth: existing JWT/
//                                   session (RequireSignedIn). Body is JSON;
//                                   the response body's `cap` field is the
//                                   base64-std-encoded ZAP wire bytes — the
//                                   cap itself is BINARY, the JSON is just
//                                   the HTTP-edge envelope.
//   GET  /v1/iam/cap/issuer-keys  — list active cap-signing public keys so
//                                   resource servers can populate their
//                                   IssuerRegistry. Cache-friendly.
//   POST /v1/iam/cap/revoke       — IAM-admin-only: append a revocation to
//                                   the local store (and, in production,
//                                   gossip the encoded record to peers via
//                                   the PubSub topic — see "open items").
//
// Audience naming convention: "<service>.<env>.<domain>", e.g.
// "ats.dev.hanzo.ai" or "kms.main.hanzo.ai". Resource servers configure
// themselves with the same string, hash it to 32 bytes, and that becomes
// CaveatAudience. Caller passes the human-readable string; the controller
// hashes it on its way into the cap.
//
// Scope naming convention: "<service>:<resource>:<action>", e.g.
// "ats:order:create" or "kms:secret:read". Scopes map onto Permissions
// bits per cap-kind; the mapping is defined per-Kind in capabilities_kinds.md.
// The controller maintains a static scope table for v1 because the bit
// budget is small (64 bits) and the kinds are few.

package controllers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hanzoai/iam/capauth"
	"github.com/zap-proto/go/cap"
)

// capIssueRequest is the body shape for POST /v1/iam/cap/issue.
type capIssueRequest struct {
	// Audience is the resource-server identifier. Hashed to 32 bytes and
	// emitted as CaveatAudience. Conventional form
	// "<service>.<env>.<domain>", e.g. "ats.dev.hanzo.ai".
	Audience string `json:"audience"`

	// Scopes is the list of "<service>:<resource>:<action>" strings the
	// caller wants on this cap. Mapped to Permissions bits via the
	// scopeBit table below.
	Scopes []string `json:"scopes"`

	// ExpiryMs is the cap lifetime in milliseconds from now. Hard-floored
	// at 0 (refused) and hard-ceilinged at the per-Kind maximum.
	ExpiryMs int64 `json:"expiry_ms"`

	// MaxDepth, if non-zero, caps how many further attenuations this cap
	// may produce. Defaults to capauth.ChainDepthMax (8).
	MaxDepth uint8 `json:"max_depth,omitempty"`

	// Kind, if non-zero, names the cap.CapKind to mint. Defaults to
	// KindIAMSession.
	Kind uint32 `json:"kind,omitempty"`

	// Holder, if non-empty, is the hex-encoded 32-byte holder hash. When
	// empty the controller uses Hash32([]byte(userId)) so the cap is
	// bound to the signed-in principal. SDK clients that bind to a
	// device pubkey should pass Hash32(devicePub) here.
	HolderHex string `json:"holder_hex,omitempty"`
}

// capIssueResponse is the body shape for POST /v1/iam/cap/issue.
type capIssueResponse struct {
	// Cap is the base64-std-encoded ZAP wire bytes. The transport here is
	// JSON because the HTTP edge is JSON; the cap itself is binary, and
	// the SDK strips the base64 immediately.
	Cap string `json:"cap"`

	// ExpiresAt is RFC3339 (UTC) for the cap's expiry. Mirrors the
	// ExpiresAt field on the wire; clients use this for token-refresh
	// scheduling without parsing the cap.
	ExpiresAt string `json:"expires_at"`

	// IssuerFingerprintHex is the hex-encoded Hash32 of the issuer's
	// public key. Resource servers index their registry by this hash;
	// clients log it for traceability.
	IssuerFingerprintHex string `json:"issuer_fingerprint_hex"`

	// CapID is the hex-encoded 32-byte cap identifier (SHA-256 of the
	// full wire bytes). Surfaced so callers can pass it to /revoke later
	// without re-decoding the cap.
	CapIDHex string `json:"cap_id_hex"`
}

// scopeBit maps a "<service>:<resource>:<action>" string to a permission
// bit. The v1 table is small and per-cap-kind because the bit budget is
// 64 — when we run out, the kinds split. Adding entries here without a
// matching capabilities_kinds.md spec is a bug; do both edits in one PR.
//
// The bit assignments are deliberately stable and additive: a service that
// learns to verify a new scope MUST NOT shift the bit, only add new ones
// in higher positions.
var scopeBit = map[uint32]map[string]uint64{
	uint32(cap.KindIAMSession): {
		"iam:whoami:read":    1 << 0,
		"iam:userinfo:read":  1 << 1,
		"iam:profile:read":   1 << 2,
		"iam:profile:write":  1 << 3,
		"iam:org:read":       1 << 4,
		"iam:org:write":      1 << 5,
	},
	uint32(cap.KindKMSAccess): {
		"kms:secret:read":  1 << 0,
		"kms:secret:write": 1 << 1,
		"kms:secret:list":  1 << 2,
		"kms:audit:read":   1 << 3,
	},
	uint32(cap.KindKMSSign): {
		"kms:sign:ed25519": 1 << 0,
		"kms:sign:secp256k1": 1 << 1,
		"kms:sign:bls":      1 << 2,
		"kms:sign:mldsa":    1 << 3,
	},
	uint32(cap.KindATSOrder): {
		"ats:order:create": 1 << 0,
		"ats:order:cancel": 1 << 1,
		"ats:order:read":   1 << 2,
		"ats:position:read": 1 << 3,
		"ats:account:read": 1 << 4,
	},
	uint32(cap.KindMPCSign): {
		"mpc:wallet:sign":   1 << 0,
		"mpc:wallet:create": 1 << 1,
		"mpc:wallet:read":   1 << 2,
	},
}

// maxLifetimePerKind is the cap-side ceiling on ExpiresAt - IssuedAt. The
// IAM admin can mint shorter caps by request; longer is refused so a
// leaked cap has a bounded blast radius.
//
// Values mirror the JWT TTLs IAM was using before the cap migration; new
// kinds get their own entry rather than borrowing.
var maxLifetimePerKind = map[uint32]time.Duration{
	uint32(cap.KindIAMSession): 24 * time.Hour,
	uint32(cap.KindKMSAccess):  1 * time.Hour,
	uint32(cap.KindKMSSign):    15 * time.Minute,
	uint32(cap.KindATSOrder):   8 * time.Hour,
	uint32(cap.KindMPCSign):    5 * time.Minute,
}

// writeCapError sends an RFC 6750–style JSON error body with the right
// status code. Mirrors writeWhoamiUnauthorized but parameterised on the
// status (some failures are 400, not 401) and without forcing the
// WWW-Authenticate header on non-auth errors.
func (c *ApiController) writeCapError(status int, code, desc string) {
	if status == http.StatusUnauthorized {
		c.Ctx.Output.Header("WWW-Authenticate",
			`ZAP error="`+code+`", error_description="`+desc+`"`)
	}
	c.Ctx.Output.SetStatus(status)
	c.Data["json"] = map[string]string{
		"error":             code,
		"error_description": desc,
	}
	c.ServeJSON()
}

// IssueCap serves POST /v1/iam/cap/issue. Caller is authenticated by the
// existing JWT/session machinery (RequireSignedIn); the cap is bound to
// the signed-in principal unless an explicit HolderHex is supplied.
//
// @Title IssueCap
// @Tag Cap API
// @Description mint a fresh ZAP capability for the signed-in principal
// @Success 200 {object} controllers.capIssueResponse
// @router /cap/issue [post]
func (c *ApiController) IssueCap() {
	userId, ok := c.RequireSignedIn()
	if !ok {
		// RequireSignedIn already wrote a 200-with-error response in the
		// legacy shape; for the cap endpoints we want a real 401 with
		// WWW-Authenticate. Override the response.
		c.writeCapError(http.StatusUnauthorized, "invalid_token",
			"caller is not signed in")
		return
	}

	var req capIssueRequest
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			"body is not valid JSON: "+err.Error())
		return
	}

	if strings.TrimSpace(req.Audience) == "" {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			"audience is required")
		return
	}
	if len(req.Scopes) == 0 {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			"scopes is required and non-empty")
		return
	}
	if req.ExpiryMs <= 0 {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			"expiry_ms must be > 0")
		return
	}

	kind := req.Kind
	if kind == 0 {
		kind = uint32(cap.KindIAMSession)
	}

	// Lifetime ceiling — refuse a cap that would outlive its kind's
	// configured maximum. Caller can request shorter; longer is no.
	maxLife, known := maxLifetimePerKind[kind]
	if !known {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("unknown kind 0x%x", kind))
		return
	}
	if time.Duration(req.ExpiryMs)*time.Millisecond > maxLife {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("expiry_ms exceeds max %s for kind 0x%x",
				maxLife, kind))
		return
	}

	// Scope -> bit conversion. Each scope must be in the per-kind table.
	scopeTable, scopeOk := scopeBit[kind]
	if !scopeOk {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("no scope table for kind 0x%x", kind))
		return
	}
	var perms uint64
	for _, s := range req.Scopes {
		bit, ok := scopeTable[s]
		if !ok {
			c.writeCapError(http.StatusBadRequest, "invalid_scope",
				fmt.Sprintf("unknown scope %q for kind 0x%x", s, kind))
			return
		}
		perms |= bit
	}

	// Holder: explicit hex wins; else bind to the userId.
	var holder [32]byte
	if req.HolderHex != "" {
		raw, err := hex.DecodeString(req.HolderHex)
		if err != nil || len(raw) != 32 {
			c.writeCapError(http.StatusBadRequest, "invalid_request",
				"holder_hex must be 64-char hex")
			return
		}
		copy(holder[:], raw)
	} else {
		holder = cap.Hash32([]byte(userId))
	}

	// Audience: human-readable string -> Hash32.
	audience := cap.Hash32([]byte(strings.TrimSpace(req.Audience)))

	// Reach for the process singleton.
	iss, err := capauth.ProcessIssuerHandle()
	if err != nil {
		c.writeCapError(http.StatusServiceUnavailable, "service_unavailable",
			"cap issuer not initialised — KMS bootstrap incomplete")
		return
	}

	depth := req.MaxDepth
	if depth == 0 {
		depth = capauth.ChainDepthMax
	}

	expiresAt := time.Now().UTC().Add(time.Duration(req.ExpiryMs) * time.Millisecond)

	// Target is a per-kind concept: for IAM sessions, the target is the
	// IAM service identity (set to a stable hash of the IAM audience).
	// For service-specific kinds, the target is the resource server
	// identity, which is the same as the audience. We use the audience
	// hash for both — the verifier matches against its own service
	// identity, so this is consistent across kinds.
	target := audience

	issued, err := iss.Issue(capauth.IssueParams{
		Kind:        cap.CapKind(kind),
		Target:      target,
		Holder:      holder,
		Permissions: perms,
		Audience:    audience,
		ExpiresAt:   expiresAt.Unix(),
		MaxDepth:    depth,
	})
	if err != nil {
		c.writeCapError(http.StatusInternalServerError, "issue_failed",
			"cap mint failed: "+err.Error())
		return
	}

	_, fingerprintHash, err := capauth.ProcessIssuerPublicKey()
	if err != nil {
		c.writeCapError(http.StatusInternalServerError, "issue_failed",
			"issuer public-key fingerprint unavailable: "+err.Error())
		return
	}

	capID := issued.ID()

	resp := capIssueResponse{
		Cap:                  base64.StdEncoding.EncodeToString(issued.Bytes()),
		ExpiresAt:            expiresAt.Format(time.RFC3339),
		IssuerFingerprintHex: capauth.Hex32(fingerprintHash),
		CapIDHex:             hex.EncodeToString(capID[:]),
	}
	c.Data["json"] = resp
	c.ServeJSON()
}

// issuerKeysResponse is the body shape for GET /v1/iam/cap/issuer-keys.
type issuerKeysResponse struct {
	// Keys is the list of active issuer keys. v1 has one entry — the
	// process singleton — but the shape supports the rotation case where
	// both the current and a previous key are still acceptable.
	Keys []capauth.IssuerKeyDescriptor `json:"keys"`

	// CacheControlSec is the recommended client-side refresh interval in
	// seconds. Matches the Cache-Control max-age header value. SDK
	// clients honour this; CLIs may not.
	CacheControlSec int `json:"cache_control_sec"`
}

// IssuerKeys serves GET /v1/iam/cap/issuer-keys. Public — no auth required;
// resource servers and SDKs both hit this on a polling cadence.
//
// @Title IssuerKeys
// @Tag Cap API
// @Description list active cap-signing public keys
// @Success 200 {object} controllers.issuerKeysResponse
// @router /cap/issuer-keys [get]
func (c *ApiController) IssuerKeys() {
	keys, err := capauth.ListIssuerKeys()
	if err != nil {
		c.writeCapError(http.StatusServiceUnavailable, "service_unavailable",
			"issuer key list unavailable: "+err.Error())
		return
	}
	// 5 minutes — long enough that resource servers don't pummel IAM,
	// short enough that a fresh key after rotation is picked up within
	// one cache cycle. Operationally aligned with the 5s revocation
	// gossip SLO (which is the upper bound on key-rotation propagation).
	const maxAgeSec = 300
	c.Ctx.Output.Header("Cache-Control",
		fmt.Sprintf("public, max-age=%d", maxAgeSec))
	c.Data["json"] = issuerKeysResponse{
		Keys:            keys,
		CacheControlSec: maxAgeSec,
	}
	c.ServeJSON()
}

// capRevokeRequest is the body shape for POST /v1/iam/cap/revoke.
type capRevokeRequest struct {
	// CapIDHex is the hex-encoded 32-byte cap ID returned by /issue's
	// `cap_id_hex` field. The revocation store keys on this value.
	CapIDHex string `json:"cap_id_hex"`

	// Reason is a short human-readable string for the audit log. Not
	// emitted on the wire; logged only.
	Reason string `json:"reason,omitempty"`
}

// capRevokeResponse acknowledges a revocation.
type capRevokeResponse struct {
	// CapIDHex echoes the revoked cap ID for client confirmation.
	CapIDHex string `json:"cap_id_hex"`

	// RevokedAt is RFC3339 UTC.
	RevokedAt string `json:"revoked_at"`
}

// RevokeCap serves POST /v1/iam/cap/revoke. IAM-admin-only: the same
// privilege required to manage other tenants' tokens. Caller MUST have
// admin privileges in the org named in the JWT — RequireAdmin enforces.
//
// v1 stores the revocation in the in-memory MemoryStore. Production gossip
// (PubSub topic "iam.cap.revocation") is a follow-up; the controller emits
// no gossip today, so revocations only take effect at THIS IAM replica
// until the topic is wired.
//
// @Title RevokeCap
// @Tag Cap API
// @Description revoke a previously-issued cap
// @Success 200 {object} controllers.capRevokeResponse
// @router /cap/revoke [post]
func (c *ApiController) RevokeCap() {
	_, ok := c.RequireAdmin()
	if !ok {
		c.writeCapError(http.StatusForbidden, "insufficient_permissions",
			"revoke requires admin")
		return
	}

	var req capRevokeRequest
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			"body is not valid JSON: "+err.Error())
		return
	}
	if req.CapIDHex == "" {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			"cap_id_hex is required")
		return
	}

	raw, err := hex.DecodeString(req.CapIDHex)
	if err != nil || len(raw) != 32 {
		c.writeCapError(http.StatusBadRequest, "invalid_request",
			"cap_id_hex must be 64-char hex")
		return
	}
	var capID [32]byte
	copy(capID[:], raw)

	store, err := capauth.ProcessStoreHandle()
	if err != nil {
		c.writeCapError(http.StatusServiceUnavailable, "service_unavailable",
			"revocation store unavailable: "+err.Error())
		return
	}
	store.Revoke(capID)

	// Also seed the legacy global revocation set so /v1/iam/whoami's
	// verifier sees the new revocation immediately.
	capauth.Revoke(capID)

	c.Data["json"] = capRevokeResponse{
		CapIDHex:  req.CapIDHex,
		RevokedAt: time.Now().UTC().Format(time.RFC3339),
	}
	c.ServeJSON()
}

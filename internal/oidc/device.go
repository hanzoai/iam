// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The RFC 8628 device authorization grant: how a machine with no browser and no
// keyboard signs in (`hanzo login` on a GPU box, over ssh, in CI). Three legs,
// each landing on an EXISTING seam rather than a parallel stack:
//
//  1. POST /v1/iam/oauth/device — the device asks for a device_code + a short
//     user_code and shows the human a verification URI.
//  2. POST /v1/iam/login {type:"device"} — the human, on any other machine,
//     proves who they are and approves the user_code (login.go).
//  3. POST /v1/iam/oauth/token grant_type=…:device_code — the device polls and
//     mints through issueTokens, the same path every other grant mints through.
//
// A device authorization IS a pending authorization code, so it is a Token row
// (Code=device_code, UserCode=user_code, User empty until approved) — not a
// process-local map, which would die on restart and never work across replicas.
//
// Client authentication follows RFC 8628 §3.1 (request) and §3.4 (poll), which
// both defer to RFC 6749 §3.2.1: a CONFIDENTIAL client (one with a registered
// secret) authenticates at both legs exactly as it would at the token endpoint;
// a PUBLIC device client (no secret — the usual CLI) is bound by its client_id
// alone. The verification_uri page a human opens is public; the JSON legs here
// are not a browser surface.

// The device grant's vocabulary. deviceCodeTTL and devicePollInterval are each
// read by the device request, the poll, and Discovery, so the lifetime a client
// is told and the lifetime enforced can never drift.
const (
	// deviceGrant is the RFC 8628 grant_type identifier.
	deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"
	// deviceCodeTTL bounds a device_code/user_code pair: long enough for a human
	// to open the link on a phone, sign in, and approve. It is deliberately NOT
	// codeTTL (5 min) — an authorization code is redeemed by software in seconds,
	// a device code waits on a person.
	deviceCodeTTL = 15 * time.Minute
	// devicePollInterval is the minimum seconds between token-endpoint polls
	// (RFC 8628 §3.5 `interval`).
	devicePollInterval = 5
)

// user_code generation. The alphabet is RFC 8628 §6.1 "unambiguous": no I, L, O,
// 0 or 1, because a human reads this off one screen and types it into another.
// Its 32 symbols make the 5-bit mask below a UNIFORM draw — a modulo over a
// non-power-of-two alphabet would bias the code and cost entropy — so 8
// characters carry a full 40 bits. The live portal normalizes a typed code to
// exactly this alphabet, uppercasing and stripping separators
// (id pkgs/auth/src/client.ts normalizeUserCode), so the minted code is the
// canonical form: uppercase, no dashes.
const (
	userCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	userCodeLen      = 8
	userCodeTries    = 5
)

// errUserCodeExhausted — every generated user_code collided with a live one.
// Astronomically unlikely (40 bits against the handful of pending codes); it
// fails closed rather than reusing a code.
var errUserCodeExhausted = errors.New("device: could not generate a free user_code")

// deviceResponse is the RFC 8628 §3.2 device authorization response. The field
// names are load-bearing: both CLIs decode exactly this shape and hard-fail on
// an empty device_code/user_code (cloud/cli/device.go, codex-rs
// login/src/oidc_device_auth.rs).
type deviceResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUri         string `json:"verification_uri"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// routeDevice registers POST /v1/iam/oauth/device on the PUBLIC group r
// (registered before the Guard, exactly like the token endpoint): the endpoint
// authenticates the CLIENT inline — a confidential client by its secret, a
// public device client by its client_id — so it needs no bearer and joins no
// allow-list, membership in this group is what makes it reachable.
func routeDevice(r zip.Router, db orm.DB) {
	r.Post(PathDevice, deviceHandler(db))
}

// deviceHandler starts a sign-in on a device with no browser and no keyboard —
// a TV, a CLI, a headless box. It returns a short code to show the person and
// the address to send them to on a phone or laptop.
//
// Nothing is granted until a human approves it there; until then the code is
// just a pending request.
func deviceHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		ctx := c.Context()

		clientID, clientSecret := clientAuth(c)
		app, err := store.GetApplicationByClientId(ctx, db, clientID)
		if err != nil {
			return tokenError(c, 500, "server_error", "")
		}
		if app == nil {
			return tokenError(c, 400, "invalid_client", "client_id is invalid")
		}
		// A confidential client (one with a registered secret) MUST authenticate
		// (RFC 8628 §3.1 → RFC 6749 §3.2.1). A public device client has no secret
		// and is identified by its client_id alone.
		if app.ClientSecret != "" &&
			subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
			return tokenErrorClient(c, "client authentication failed")
		}
		if !appGrants(app, deviceGrant) {
			return tokenError(c, 400, "unsupported_grant_type", "the application does not permit the device grant")
		}

		deviceCode, err := newOpaqueToken()
		if err != nil {
			return tokenError(c, 500, "server_error", "")
		}
		userCode, err := newUserCode(ctx, db)
		if err != nil {
			return tokenError(c, 500, "server_error", "")
		}

		// One row IS the pending authorization: Code is the device_code the
		// machine polls with, UserCode the code its human transcribes, and an
		// empty User means nobody has approved yet.
		row := &schema.Token{
			Owner:        app.Owner,
			Application:  app.Name,
			Organization: app.Organization,
			Code:         deviceCode,
			UserCode:     userCode,
			Scope:        param(c, "scope"),
			TokenType:    "Bearer",
			CodeExpireIn: nowFunc().Add(deviceCodeTTL).Unix(),
		}
		row.Name = "dc-" + deviceCode[:24]
		if err := store.PersistToken(ctx, db, row); err != nil {
			return tokenError(c, 500, "server_error", "")
		}

		// Both URIs point at the SPA approval page a human opens, never at this
		// JSON API. The complete form is a PATH segment because that is the route
		// the page is registered on (/login/oauth/device/:userCode).
		verify := tokenIssuer(c) + PathDeviceVerify
		return c.JSON(200, deviceResponse{
			DeviceCode:              deviceCode,
			UserCode:                userCode,
			VerificationUri:         verify,
			VerificationUriComplete: verify + "/" + userCode,
			ExpiresIn:               int(deviceCodeTTL.Seconds()),
			Interval:                devicePollInterval,
		})
	}
}

// deviceCodeGrant is the device's poll (RFC 8628 §3.4), dispatched from the one
// token endpoint. It authenticates the client (confidential by secret, public by
// client_id) and answers `authorization_pending` until a human approves, then
// mints exactly once. The human who authenticated and approved at the
// verification URI IS the end-user authentication.
func deviceCodeGrant(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	presented := param(c, "device_code")
	if presented == "" {
		return tokenError(c, 400, "invalid_request", "device_code is required")
	}
	row, err := store.GetTokenByCode(ctx, db, presented)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	// Unknown, not a device authorization, or already redeemed. isDevice is what
	// stops an authorization code being redeemed HERE, where neither its PKCE
	// challenge nor its redirect_uri is verified.
	if row == nil || !isDevice(row) || row.CodeIsUsed {
		return deviceDead(c)
	}
	// Expired — reap it on the way past, so a dead authorization does not linger.
	if expired(row.CodeExpireIn, now) {
		_ = store.DeleteToken(ctx, db, row)
		return deviceDead(c)
	}

	app, err := resolveTokenApp(ctx, db, row)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if app == nil {
		return tokenError(c, 400, "invalid_grant", "the device code is invalid")
	}
	clientID, clientSecret := clientAuth(c)
	if deviceClientMismatch(app, clientID) {
		return tokenError(c, 400, "invalid_grant", "the device_code was not issued to this client")
	}
	// A confidential client authenticates on EVERY poll (RFC 8628 §3.4 → RFC 6749
	// §3.2.1), checked before the pending/mint split so an unauthenticated
	// confidential poll never even learns the grant's approval state. A public
	// device client has no secret and is bound by its client_id alone (above).
	if app.ClientSecret != "" &&
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
		return tokenErrorClient(c, "client authentication failed")
	}
	// Re-gated at redemption, not only at the request: an application whose device
	// grant was withdrawn between the two must not still mint.
	if !appGrants(app, deviceGrant) {
		return tokenError(c, 400, "unsupported_grant_type", "the application does not permit the device grant")
	}
	// Not approved yet: leave the row exactly as it is — the device keeps polling.
	if row.User == "" {
		return tokenError(c, 400, "authorization_pending", "the device authorization is pending approval")
	}

	// One-shot: burn the approval BEFORE minting, so any later poll finds the row
	// already redeemed rather than minting a second token off one approval. Like
	// the authorization-code grant beside it this is a read-modify-write, not a
	// compare-and-swap: two polls landing inside the same write window could still
	// both mint. They mint the same user, app, scope and refresh family, so the
	// duplicate is contained (revoking the family revokes both) — a real CAS is a
	// property the Token row would have to carry for every grant, not just this one.
	row.CodeIsUsed = true
	if err := store.SaveToken(ctx, db, row); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	resp, err := issueTokens(ctx, db, c, app, row, newFamilyID(row), now)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if err := store.SaveToken(ctx, db, row); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	return c.JSON(200, resp)
}

// approveDevice binds an authenticated human's identity onto a pending device
// authorization — the act that lets the device's next poll mint. The row's
// application and scope stay authoritative for that mint: the portal app the
// browser happens to be on is irrelevant to WHAT is being approved, so it is
// never read here. Called from the login handler once the credential check has
// already proven who the approver is.
func approveDevice(c *zip.Ctx, db orm.DB, user *schema.User, userCode string) error {
	// ONE opaque refusal for unknown / not-a-device / expired / already-approved /
	// already-redeemed. The user_code is only 40 bits — the one secret in this
	// flow — so an answer that distinguished those cases would turn this page into
	// an oracle for hunting live codes.
	const refuse = "the user code is invalid or expired"

	ctx := c.Context()
	row, err := store.GetTokenByUserCode(ctx, db, userCode)
	if err != nil {
		return httpx.Err(c, refuse)
	}
	if row == nil || !isDevice(row) || row.CodeIsUsed || row.User != "" ||
		expired(row.CodeExpireIn, nowFunc()) {
		return httpx.Err(c, refuse)
	}
	// Tenant boundary: a user in org A must not approve a device sign-in bound to
	// an app in org B (a confused deputy — brands seed same-named superusers). The
	// org compared is the DEVICE row's, captured when the code was issued. A
	// SuperAdmin — a member of the reserved admin org, the one predicate — crosses
	// tenants deliberately: that is the identity an operator signs a CLI into any
	// brand's app with. An unresolvable tenant fails closed.
	if row.Organization == "" {
		return httpx.Err(c, refuse)
	}
	if !store.IsSuperAdmin(user.Owner) && user.Owner != row.Organization {
		return httpx.Err(c, "your organization may not approve this device sign-in")
	}

	row.User = user.Owner + "/" + user.Name
	if err := store.SaveToken(ctx, db, row); err != nil {
		return httpx.Err(c, refuse)
	}
	return httpx.Ok(c, row.User)
}

// deviceDead is the one answer for a device_code that cannot be redeemed —
// unknown, not a device authorization, already redeemed, or expired. To the
// client those are the same fact (this code is dead, start over), so they get
// the same words: sharing one answer makes that structural rather than a
// coincidence of copied strings.
func deviceDead(c *zip.Ctx) error {
	return tokenError(c, 400, "expired_token", "the device code is expired or already redeemed")
}

// isDevice reports whether a code row is an RFC 8628 device authorization rather
// than an authorization code. Both kinds live in Token.Code, so every grant
// checks the kind before redeeming: an authorization code must never be redeemed
// at the device grant, which verifies neither PKCE nor redirect_uri, and a
// device code must never be redeemed at the authorization-code grant, which
// would mint on a row no human has approved. The user_code IS the
// discriminator — only a device authorization has one.
func isDevice(tok *schema.Token) bool { return tok != nil && tok.UserCode != "" }

// deviceClientMismatch reports whether clientID is NOT the client the device
// authorization was issued to (RFC 8628 §3.4). Without this an approval for app
// A is redeemable as app B: a confused deputy that hands the caller a token for
// the wrong audience. Pure, so the binding is unit-testable.
func deviceClientMismatch(app *schema.Application, clientID string) bool {
	return app == nil ||
		subtle.ConstantTimeCompare([]byte(clientID), []byte(app.ClientId)) != 1
}

// appGrants reports whether app permits grant — the per-application grant gate
// (v1 IsGrantTypeValid, object/token_oauth.go:605). A grant must be DECLARED on
// the application to be usable, so an app that never enabled the device grant can
// never mint a device token. Fail-closed by construction: every live application
// declares its grant set, so an app with none permits none.
func appGrants(app *schema.Application, grant string) bool {
	if app == nil {
		return false
	}
	for _, g := range app.GrantTypes {
		if g == grant {
			return true
		}
	}
	return false
}

// expired reports whether a unix deadline has passed. A zero deadline never
// expires (the v1 convention for "unset").
func expired(deadline int64, now time.Time) bool {
	return deadline != 0 && now.Unix() > deadline
}

// newUserCode mints a user_code that no live row already carries. Each attempt
// REGENERATES the candidate — a loop that re-tests one fixed code could never
// clear a collision.
func newUserCode(ctx context.Context, db orm.DB) (string, error) {
	for range userCodeTries {
		code, err := randomUserCode()
		if err != nil {
			return "", err
		}
		row, err := store.GetTokenByUserCode(ctx, db, code)
		if err != nil {
			return "", err
		}
		if row == nil {
			return code, nil
		}
	}
	return "", errUserCodeExhausted
}

// randomUserCode draws userCodeLen symbols uniformly from userCodeAlphabet.
func randomUserCode() (string, error) {
	buf := make([]byte, userCodeLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = userCodeAlphabet[buf[i]&0x1f]
	}
	return string(buf), nil
}

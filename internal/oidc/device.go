// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/schema"
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
	deviceCodeTTL = 10 * time.Minute
	// devicePollInterval is the minimum seconds between token-endpoint polls
	// (RFC 8628 §3.5 `interval`). A poll that finds the request still pending and
	// comes sooner than deviceTooFast after the last one is told slow_down; the
	// allowance under the interval is network jitter, not a licence.
	devicePollInterval = 5
	deviceTooFast      = 4000 // milliseconds
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
//
// The sibling POST names the client a pending user_code belongs to. It is on the
// same public group and authenticates the same way every browser path here does:
// by the session cookie, resolved inline.
//
// POST for a read, deliberately, and for the reason RFC 7662 introspection beside
// it is POST: the argument is a SECRET. A user_code in a request line is copied
// into ingress and proxy access logs, which a POST body is not — and this flow's
// own approval page ships a scrubUrl() to keep the code out of the address bar,
// so putting it back into every request line would undo that on the server side.
func routeDevice(r *zip.Group, db orm.DB) {
	r.Raw(http.MethodPost, PathDevice, deviceHandler(db))
	r.Raw(http.MethodPost, PathDeviceInfo, deviceInfoHandler(db))
}

// deviceInfo is what the approval page must show a human: WHICH application is
// asking to sign in. Both fields come off the pending device code's own
// application — never off the portal the browser happens to be on.
type deviceInfo struct {
	ClientId    string `json:"clientId"`
	DisplayName string `json:"displayName"`
	// Platform says the application is one the platform itself declares, and
	// Organization whose it is otherwise. A name is the application's own word for
	// itself, so a page that shows one must also say whether it is Hanzo's: a
	// tenant can register an application and name it anything.
	Platform     bool   `json:"platform"`
	Organization string `json:"organization"`
	// Requested says where and when the device authorization was started, and Scope
	// what it would be allowed to do. The person approving is not the person who
	// started it, unless it is their own terminal, and a stranger's request cannot
	// hide that it comes from somewhere else; Scope is what the grant carries (the
	// application's, never the requester's word for it).
	Requested deviceRequest `json:"requested"`
	Scope     []string      `json:"scope"`
	// Account is the person the page is signed in as, which is who an approval
	// binds the device to. The page shows it and returns Sub as the approval's
	// loginHint, so the account approved is the one that was looked at and not
	// whichever session another tab made the current one in between.
	Account deviceAccount `json:"account"`
	// Agent is set when the code is an agent registration rather than a device
	// sign-in (agent.go): approving it makes a service account in Organization, the
	// signed-in person's own org, for the program that registered as Registration.
	// The page says so, because that is a different act from signing a device in.
	Agent *agentRequest `json:"agent,omitempty"`
}

// agentRequest is what approving an agent registration does.
type agentRequest struct {
	Registration string `json:"registration"`
	Organization string `json:"organization"`
}

// deviceRequest is where a device authorization was started.
type deviceRequest struct {
	Ip      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	At      int64  `json:"at,omitempty"`
}

// deviceAccount names the person a device approval would be made as.
type deviceAccount struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// deviceInfoHandler answers "what am I approving?" for a pending device code.
//
// The approval page exists to tell a human WHICH application they are authorizing;
// a page that names any other one defeats the control it implements. The client is
// a property of the CODE, not of the page or of whatever app the browser happens
// to be signed in to, so it is read from the code's row here and nowhere else.
//
// Requires a signed-in session, and answers with the same ONE opaque refusal
// approveDevice uses. That is deliberate: the user_code is only 40 bits and is the
// one secret in this flow, so an unauthenticated lookup — or one that
// distinguished unknown from expired from already-approved — would be an oracle
// for hunting live codes. Gated and opaque, it reveals strictly less than the
// approval the same caller could already attempt.
func deviceInfoHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		ctx := c.Context()

		// The identity is the browser's session, exactly as the approval itself
		// resolves it. Not signed in is not a refusal to explain — it is the
		// page's cue to sign the human in first, so it carries the stable code
		// the SPA branches on.
		owner, name, ok := sessions.Resolve(ctx, c.Fiber(), db)
		if !ok {
			return httpx.ErrCode(c, "please sign in first", CodeLoginRequired)
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil || user == nil || user.IsForbidden || user.IsDeleted {
			return httpx.ErrCode(c, "please sign in first", CodeLoginRequired)
		}

		// JSON body from the approval page, form/query for anything else — the same
		// bind-then-fall-back login uses, so one endpoint serves both
		// without a second spelling of the request.
		var f struct {
			UserCode string `json:"userCode"`
		}
		_ = c.Bind(&f)
		userCode := f.UserCode
		if userCode == "" {
			userCode = param(c, "userCode")
		}

		const refuse = "the user code is invalid or expired"
		// One refusal for every way a look can fail, the org mismatch included: the
		// caller learns nothing about a code that is not theirs to approve. Each miss
		// is counted against the account, and an account past its budget gets that
		// refusal for every answer.
		row, app := lookDevice(ctx, db, user, userCode)
		if row == nil {
			return httpx.Err(c, refuse)
		}
		label := app.DisplayName
		if label == "" {
			label = app.Name
		}
		who := user.DisplayName
		if who == "" {
			who = user.Name
		}
		info := deviceInfo{
			ClientId:     app.ClientId,
			DisplayName:  label,
			Platform:     app.Platform,
			Organization: app.Organization,
			Requested:    deviceRequest{Ip: row.RequestIp, Country: row.RequestCountry, At: row.Requested},
			Scope:        strings.Fields(row.Scope),
			Account:      deviceAccount{Sub: subjectOf(user), Name: who, Email: user.Email},
		}
		if isAgent(row) {
			info.Agent = &agentRequest{Registration: registrationOf(row), Organization: user.Owner}
		}
		return httpx.Ok(c, info)
	}
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
		if !app.Proves(clientSecret) {
			return tokenErrorClient(c, "client authentication failed")
		}
		if !appGrants(app, deviceGrant) {
			return tokenError(c, 400, "unsupported_grant_type", "the application does not permit the device grant")
		}
		// The approval page lives at the application's sign-in origin, which is the
		// issuer unless the operator says otherwise; with no issuer there is nowhere
		// to send the person, so nothing is minted.
		iss, err := tokenIssuer(c)
		if err != nil {
			return tokenError(c, 500, "server_error", "")
		}

		// The start asks for no credential, so it is bounded: the scope as authorize
		// bounds its own, and how often one client and one address may start. What is
		// refused is never written.
		asked := param(c, "scope")
		if len(asked) > deviceScopeLimit {
			return tokenError(c, 400, "invalid_scope", "scope is too long")
		}
		now := nowFunc()
		ip, country := requesterOf(c)
		if !deviceClientStarts.within("c:"+app.ClientId, now) || (ip != "" && !deviceAddressStarts.within("i:"+ip, now)) {
			return tokenError(c, 429, "slow_down", "too many sign-ins are being started; try again in a minute")
		}
		sweepDevices(ctx, db, now)

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
			// What the grant carries is what the application may have of what was
			// asked, never the asker's word: it is shown to the approver and it is
			// the scope of the token the device is minted.
			Scope:          forgeScoped(app, strings.Join(grantedScope(app, asked), " ")),
			TokenType:      "Bearer",
			CodeExpireIn:   now.Add(deviceCodeTTL).Unix(),
			RequestIp:      ip,
			RequestCountry: country,
			Requested:      now.Unix(),
		}
		row.Name = "dc-" + deviceCode[:24]
		if err := store.PersistToken(ctx, db, row); err != nil {
			return tokenError(c, 500, "server_error", "")
		}

		verify, complete := verificationURIs(app, iss, userCode)
		return c.JSON(200, deviceResponse{
			DeviceCode:              deviceCode,
			UserCode:                userCode,
			VerificationUri:         verify,
			VerificationUriComplete: complete,
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
	if !app.Proves(clientSecret) {
		return tokenErrorClient(c, "client authentication failed")
	}
	// Re-gated at redemption, not only at the request: an application whose device
	// grant was withdrawn between the two must not still mint.
	if !appGrants(app, deviceGrant) {
		return tokenError(c, 400, "unsupported_grant_type", "the application does not permit the device grant")
	}

	// What state the row is in, and what this poll does to it, is decided on the row
	// as the lock holder reads it (store.WithToken), never on the copy read above: an
	// approval, a refusal and another poll all land on this row, and each used to
	// decide on its own stale copy and overwrite the others. Here the burn is atomic,
	// so a refusal never lands beside a mint and two polls never both mint. A person's
	// refusal is told once (RFC 8628 §3.5) and burned, after the client authenticates
	// like the pending answer, so an unauthenticated poll never learns what was
	// decided. A poll that finds the request pending and comes sooner than the
	// interval allows is told slow_down.
	var verdict string
	err = store.WithToken(ctx, db, row, func(t *schema.Token) (bool, error) {
		switch {
		case t.CodeIsUsed || expired(t.CodeExpireIn, now):
			verdict = "dead"
			return false, nil
		case t.Denied:
			t.CodeIsUsed, verdict = true, "denied"
			return true, nil
		case t.User == "":
			at := now.UnixMilli()
			if t.Polled != 0 && at-t.Polled < deviceTooFast {
				verdict = "slow"
				return false, nil
			}
			t.Polled, verdict = at, "pending"
			return true, nil
		default:
			t.CodeIsUsed, verdict = true, "mint"
			return true, nil
		}
	})
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	switch verdict {
	case "dead":
		return deviceDead(c)
	case "denied":
		return tokenError(c, 400, "access_denied", "the person refused the sign-in")
	case "slow":
		return tokenError(c, 400, "slow_down", "poll no faster than the interval")
	case "pending":
		return tokenError(c, 400, "authorization_pending", "the device authorization is pending approval")
	}

	// Minted exactly once: the row was burned under the lock above, so any later poll
	// finds it redeemed. Like the authorization-code grant beside it the tokens are
	// issued and the row saved after, which nothing else can change now.
	resp, err := issueTokens(ctx, db, c, app, row, newFamilyID(row), now)
	if err != nil {
		return mintError(c, err)
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
	// already-redeemed / not-yours. The user_code is only 40 bits — the one secret in
	// this flow — so an answer that distinguished those cases would turn this page
	// into an oracle for hunting live codes.
	const refuse = "the user code is invalid or expired"

	ctx := c.Context()
	row, app := lookDevice(ctx, db, user, userCode)
	if row == nil {
		return httpx.Err(c, refuse)
	}
	// Decided on the row as the lock holder reads it: a refusal or a second approval
	// that landed since the look has already ended the request.
	who := user.Owner + "/" + user.Name
	if err := store.WithToken(ctx, db, row, func(t *schema.Token) (bool, error) {
		if !pending(t) {
			return false, errNotPending
		}
		t.User = who
		return true, nil
	}); err != nil {
		return httpx.Err(c, refuse)
	}
	// A SuperAdmin approving a sign-in to another organization's application is
	// platform authority crossing a tenant, so it goes on the SuperAdmin trail.
	if user.SuperAdmin() && user.Owner != row.Organization {
		store.Record(ctx, db, &schema.AuditLog{
			Owner:        user.Owner,
			Organization: row.Organization,
			User:         who,
			ClientIp:     httpx.ClientIP(c),
			Method:       c.Method(),
			RequestUri:   c.Path(),
			Action:       schema.ActionSuperAdmin,
			Object:       app.ClientId,
			StatusCode:   200,
		})
	}
	return httpx.Ok(c, who)
}

// errNotPending is a device authorization that stopped being pending between the
// look and the write: approved, refused, redeemed or expired.
var errNotPending = errors.New("device: not pending")

// denyDevice is the person's refusal of a pending device authorization: the
// device's next poll is told access_denied (RFC 8628 §3.5) and the code is dead,
// where closing the tab would leave it approvable by anyone holding it for the
// rest of its life. It rides the same seam as the approval (login.go, type=device_deny),
// so the session, the same-origin rule, the account the page showed and the
// tenant boundary are the approval's by construction, and it answers refusals in
// the approval's one opaque sentence.
func denyDevice(c *zip.Ctx, db orm.DB, user *schema.User, userCode string) error {
	const refuse = "the user code is invalid or expired"

	ctx := c.Context()
	row, _ := lookDevice(ctx, db, user, userCode)
	if row == nil {
		return httpx.Err(c, refuse)
	}
	if err := store.WithToken(ctx, db, row, func(t *schema.Token) (bool, error) {
		if !pending(t) {
			return false, errNotPending
		}
		t.Denied = true
		return true, nil
	}); err != nil {
		return httpx.Err(c, refuse)
	}
	return httpx.Ok(c, "denied")
}

// lookDevice resolves the pending device authorization userCode names for a
// signed-in person, and the application it is for, or nil when there is none they
// may act on. Looking, approving and refusing all begin here, so what you may look at
// is exactly what you may approve, and every way it can fail is the same nil: an
// unknown code, a spent one, an expired one, one for a tenant you may not approve.
// Each failure is a guess as far as this can tell, so it is counted against the
// account (deviceMisses), and an account past its budget is refused whatever it asks.
//
// An agent registration rides this too, under its own rule (mayClaim): only the
// account whose verified address the agent named, and only an admin of a tenant
// home org. Any other account is refused in the same words as a code that is not
// there, so the page reveals nothing about a registration it may not approve.
func lookDevice(ctx context.Context, db orm.DB, user *schema.User, userCode string) (*schema.Token, *schema.Application) {
	now := nowFunc()
	who := subjectOf(user)
	if deviceMisses.spent(who, now) {
		return nil, nil
	}
	row, err := store.GetTokenByUserCode(ctx, db, userCode)
	if err == nil && pending(row) && row.Organization != "" {
		if app, err := resolveTokenApp(ctx, db, row); err == nil && app != nil {
			if (isAgent(row) && mayClaim(user, row)) || (isDevice(row) && mayApprove(user, row, app)) {
				return row, app
			}
		}
	}
	missed(who, now)
	return nil, nil
}

// devicePurged is when dead authorizations were last swept, in unix seconds.
var devicePurged atomic.Int64

// sweepDevices removes the device authorizations nobody approved and whose code has
// expired, a batch at most once a minute per process: a start writes a row and
// nothing else deletes one that is never polled again.
func sweepDevices(ctx context.Context, db orm.DB, now time.Time) {
	last := devicePurged.Load()
	if now.Unix()-last < 60 || !devicePurged.CompareAndSwap(last, now.Unix()) {
		return
	}
	if _, err := store.PurgeDeviceCodes(ctx, db, now, devicePurgeBatch); err != nil {
		log.Printf("device: sweep: %v", err)
	}
}

// pending reports whether row is a device authorization or an agent registration
// still waiting for a person: not redeemed, not approved, not refused and not
// expired. Looking, approving and refusing each ask it, so the three can never
// disagree about which codes are live.
func pending(row *schema.Token) bool {
	return row != nil && asksPerson(row) && !row.CodeIsUsed && row.User == "" && !row.Denied &&
		!expired(row.CodeExpireIn, nowFunc())
}

// verificationURIs are the two addresses a person is sent to with userCode, for a
// code app issued under iss: the approval page, and the page with the code filled
// in. Both point at the SPA page a human opens, never at the JSON API. The page is
// where the application says its people sign in (verificationOrigin), the issuer's
// own when it says nothing the operator has configured. The device grant and an
// agent registration (agent.go) send a person to the same page, so they read it
// here.
func verificationURIs(app *schema.Application, iss, userCode string) (verify, complete string) {
	origin := verificationOrigin(app, iss)
	verify = origin + PathDeviceVerify
	// The complete form is a PATH segment on the issuer's own SPA, because that is
	// the route the page is registered on (/login/oauth/device/:userCode). On the
	// brand's own site the code rides the FRAGMENT: a fragment reaches no server, so
	// the code is in no access log, no CDN's analytics and no Referer, which a path
	// segment is in all three.
	complete = verify + "/" + userCode
	if origin != normalizeIssuer(iss) {
		complete = verify + "#" + userCode
	}
	return verify, complete
}

// verificationOrigin is the origin of the page a person opens to approve a
// device sign-in for app, whose issuer is iss.
//
// It is the origin of the application's own SigninUrl (where the application says
// its people sign in) when the operator has configured that origin as a sign-in
// origin of THIS issuer, and the issuer itself otherwise. The application says
// which; the operator decides whether it may: SigninUrl is a field an
// organization writes for its own applications, so it selects among the origins
// IAM_FEDERATION_ORIGIN_MAP names and can name no other. A link to a host IAM
// does not sign people in at, or to another brand's, would send a person with a
// code to a page that cannot approve it, or to a page that is not ours.
//
// Only an origin is taken from it. The path is the approval page's, never the
// SigninUrl's, and the userinfo, query and fragment of a SigninUrl never reach a
// link.
//
// Only an application the platform declares (schema.Application.Platform, which
// only a SuperAdmin may set) is sent to the brand's own site. The approval page
// shows the application's name, which its registrant chose, so a tenant's
// application on the brand's host would borrow the brand's standing for a name of
// its own choosing; it keeps the issuer's page, as every application did.
func verificationOrigin(app *schema.Application, iss string) string {
	iss = normalizeIssuer(iss)
	if app == nil || !app.Platform || strings.TrimSpace(app.SigninUrl) == "" {
		return iss
	}
	u, err := url.Parse(strings.TrimSpace(app.SigninUrl))
	if err != nil || u.User != nil || u.Host == "" {
		return iss
	}
	origin, err := signinOrigin("https://" + u.Host)
	if err != nil || u.Scheme != "https" {
		return iss
	}
	if configuredSignin(origin, iss) {
		return origin
	}
	return iss
}

// configuredSignin reports whether origin is a sign-in origin the operator
// configured for the issuer iss: the issuer's own, or a value of
// IAM_FEDERATION_ORIGIN_MAP whose host belongs to the same brand. A host the
// issuer map does not name resolves to the default issuer, so an origin of another
// brand is refused here exactly as the boot check refuses a map that would send
// one there (signinOriginsTerminal).
func configuredSignin(origin, iss string) bool {
	if origin == iss {
		return true
	}
	r := activeFederationResolver.Load()
	if r == nil {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host, err := resolveIssuer(u.Host)
	if err != nil || normalizeIssuer(host) != iss {
		return false
	}
	for _, v := range r.byHost {
		if v == origin {
			return true
		}
	}
	return false
}

// mayApprove reports whether user may look at and approve the pending device
// authorization row, which the application app issued.
//
// A user in org A must not approve a device sign-in bound to an app confined to
// org B (a confused deputy — brands seed same-named superusers). The org compared
// is the DEVICE row's, captured when the code was issued. An app that serves any
// org admits any org that is not reserved — the same rule its authorization code
// is minted under (MintFor), so a self-service account in an org of its own
// approves `hanzo auth login` exactly as it signs in to the console. A SuperAdmin
// (schema.User.SuperAdmin) crosses tenants for the platform's own applications and
// for those alone: that is the identity an operator signs a CLI into any brand's app
// with, and approveDevice records it. A tenant's application is its tenant's.
func mayApprove(user *schema.User, row *schema.Token, app *schema.Application) bool {
	if user.Owner == row.Organization || (user.SuperAdmin() && app.Platform) {
		return true
	}
	return app.ServesAnyOrg() && !policy.IsReservedOrg(user.Owner)
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
// discriminator — only a row a person is asked to approve has one — and of those,
// an agent registration (isAgent) is not a device authorization: its claim token is
// never a device_code, so the device poll never redeems one.
func isDevice(tok *schema.Token) bool { return asksPerson(tok) && !isAgent(tok) }

// asksPerson reports whether a code row waits on a person typing its user_code at
// the approval page: a device authorization or an agent registration. Neither is an
// authorization code, and the approval page serves both.
func asksPerson(tok *schema.Token) bool { return tok != nil && tok.UserCode != "" }

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

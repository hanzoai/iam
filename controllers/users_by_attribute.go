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

// Server-to-server soft-signal lookup: "does a user row with this
// phone/email already exist in my org?" Used by /ATS/TA during
// onboarding so the caller can decide whether to attach to an existing
// user or mint a new one — WITHOUT exposing user enumeration to anyone
// holding a user JWT.
//
// Threat model:
//   Asset    — user PII (phone/email/name/displayName/id) per org.
//   Adversary — a holder of a user JWT (authorization_code or password
//               grant). If they could call this endpoint they'd have an
//               unbounded enumeration oracle: probe every phone in the
//               world, get back "yes/no this user exists, here's their
//               name and email". Hard NO.
//   Surface  — internal-only. The only legitimate callers are
//               server-to-server: BD/ATS/TA service apps holding their
//               own client_credentials JWT.
//
// Defenses (defense in depth — each layer assumes the previous failed):
//   1. Auth: JWT must have user.Type=="application" (which client_credentials
//      mints; user JWTs are "normal-user"). Anything else → 403.
//      Bare anon (no JWT) → 401.
//   2. Allowlist: caller's clientId (== application.Name for the synthetic
//      app-user) must appear in env IAM_BY_ATTRIBUTE_ALLOWLIST. Empty
//      allowlist == reject all (fail-secure default). Anything else → 403.
//   3. Org scope: owner is read from the JWT (via session/context) — the
//      handler IGNORES any `owner=` query/body param. No cross-tenant
//      lookups; never a way for caller A to probe org B.
//   4. Rate limit: 10 req/min per clientId in-memory bucket. Excess →
//      429. IAM runs single-replica per cluster, so a global map
//      suffices. IP is NOT in the key — X-Forwarded-For is
//      client-controlled at this layer (the ingress does not pin
//      trustedIPs), so IP-keyed buckets would be bypassable by header
//      rotation. clientId alone is the right key because the attacker
//      cannot rotate it without owning a separate allowlisted
//      credential.
//   5. Audit: every probe is logged via object.AddRecord (the existing
//      tamper-evident audit pipeline) with caller clientId, source IP,
//      attribute type, and result-count — NEVER the probed phone/email
//      value itself, NEVER the matched rows. Audits a hit-vs-miss, not
//      the values.
//   6. Result cap: hard 25, no offset. No way to walk past the cap with
//      a multiplier; you get the first 25 (almost always 0 or 1 in
//      practice) and that's it.
//   7. Soft signal: NEVER 404 on miss. A 200 + empty array is the only
//      "miss" outcome. 4xx implies a configuration problem (auth/scope),
//      not "the user does not exist".

package controllers

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/beego/v2/core/logs"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// byAttributeMaxResults is the hard cap on results returned in a single
// probe. No offset parameter is honored — pagination across this surface
// would defeat the enumeration mitigation.
const byAttributeMaxResults = 25

// byAttributeRateBurst / byAttributeRateWindow define the per-clientId
// bucket: 10 probes per rolling 60 seconds. IP is intentionally NOT in
// the key — see byAttributeRateLimit for the threat-model rationale.
const (
	byAttributeRateBurst  = 10
	byAttributeRateWindow = 60 * time.Second
)

// UserByAttribute is the minimal projection of a User row returned to a
// server-to-server caller. We deliberately omit secret-bearing fields
// (password/salt/passwordType/totp/webauthn/...) and high-PII fields
// (idCard, dateOfBirth, addresses). The caller asked "do you know this
// person?" — they get back the smallest useful answer.
type UserByAttribute struct {
	Id          string `json:"id"`
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	DisplayName string `json:"displayName"`
	CreatedTime string `json:"createdTime"`
}

// byAttributeBucket is the in-process per-key rate-limit bucket.
type byAttributeBucket struct {
	stamps []time.Time
}

var (
	byAttrBuckets   sync.Map // map[bucketKey]*byAttributeBucket
	byAttrJanitorMu sync.Mutex
	byAttrLastSweep time.Time

	// digitsOnly strips everything that is not a digit. Used in phone
	// normalization to peel formatting (+, spaces, dashes, parens).
	digitsOnly = regexp.MustCompile(`[^0-9]`)

	// byAttrResolveClaims is the seam for the JWT-verifying dependency.
	// Production wires it to the real DB-backed resolver below;
	// controllers/users_by_attribute_test.go swaps in a deterministic
	// fake so unit tests do not require a live xorm engine. Indirection
	// via a package var (vs interface field) is intentional: zero
	// surface change on the controller, zero allocation per request.
	byAttrResolveClaims = defaultResolveServiceClaims

	// byAttrAudit is the seam for the audit-log dependency. Production
	// writes through object.AddRecord (which requires xorm). Tests
	// substitute a no-op (or capturing) implementation. Keeping this
	// behind a var means the controller code path is identical between
	// prod and test — only the sink moves.
	byAttrAudit = defaultAuditByAttributeProbe
)

// init seeds byAttrLastSweep so the very first request does NOT spawn a
// concurrent sweep goroutine (whose Range over an empty bucket map is a
// no-op but races with test setup that re-creates the bucket Map). The
// production effect is identical (we still sweep every 5 minutes); the
// test-stability effect is "no surprise goroutine in flight".
func init() {
	byAttrJanitorMu.Lock()
	byAttrLastSweep = time.Now()
	byAttrJanitorMu.Unlock()
}

// byAttributeAllowedClients parses the IAM_BY_ATTRIBUTE_ALLOWLIST env var
// into a set. Empty/unset env = empty set = reject all (fail-secure).
// Whitespace trimmed; empty entries dropped.
//
//	IAM_BY_ATTRIBUTE_ALLOWLIST=liquidity-bd,liquidity-ats,liquidity-ta
func byAttributeAllowedClients() map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv("IAM_BY_ATTRIBUTE_ALLOWLIST"))
	set := map[string]struct{}{}
	if raw == "" {
		return set
	}
	for _, item := range strings.Split(raw, ",") {
		v := strings.TrimSpace(item)
		if v != "" {
			set[v] = struct{}{}
		}
	}
	return set
}

// byAttributeRateLimit applies a sliding-window token bucket keyed
// SOLELY on clientId. Returns true if the request should be allowed,
// false if it should be rejected with 429.
//
// We deliberately do NOT key on IP. The IP would be sourced from
// X-Forwarded-For / X-Real-IP headers, which are CLIENT-CONTROLLED.
// The Hanzo ingress (Traefik fork) at the time
// of writing does not set forwardedheaders.trustedIPs, so a malicious
// caller can rotate XFF per request and bypass an IP-keyed limiter
// trivially:
//
//	for i := 0; i < 1_000_000; i++ {
//	    req.Header.Set("X-Forwarded-For", randIP()) // gets its own bucket
//	}
//
// 10/min/clientId is sufficient on its own: an attacker cannot rotate
// clientId because that requires owning a separate, allowlisted
// client_credentials secret — they would need to have already breached
// a second tenant service. The bucket key collapse also simplifies
// the data structure (one entry per service principal, bounded by the
// allowlist size).
//
// IP-based protection belongs at the ingress layer
// (forwardedheaders.insecure=false + trustedIPs=<ingress CIDR>) and
// is tracked as a follow-up issue in the universe repo. At THIS layer
// IP is untrusted, so we ignore it.
func byAttributeRateLimit(clientId string) bool {
	if clientId == "" {
		return false
	}
	key := clientId
	now := time.Now()
	cutoff := now.Add(-byAttributeRateWindow)

	val, _ := byAttrBuckets.LoadOrStore(key, &byAttributeBucket{})
	bucket := val.(*byAttributeBucket)

	kept := bucket.stamps[:0]
	for _, t := range bucket.stamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= byAttributeRateBurst {
		bucket.stamps = kept
		return false
	}
	bucket.stamps = append(kept, now)

	byAttrJanitorMu.Lock()
	if now.Sub(byAttrLastSweep) > 5*time.Minute {
		byAttrLastSweep = now
		byAttrJanitorMu.Unlock()
		go byAttributeSweep(cutoff)
	} else {
		byAttrJanitorMu.Unlock()
	}
	return true
}

func byAttributeSweep(cutoff time.Time) {
	byAttrBuckets.Range(func(k, v interface{}) bool {
		bucket := v.(*byAttributeBucket)
		fresh := false
		for _, t := range bucket.stamps {
			if t.After(cutoff) {
				fresh = true
				break
			}
		}
		if !fresh {
			byAttrBuckets.Delete(k)
		}
		return true
	})
}

// phoneCandidates returns every reasonable stored variant for a raw phone
// query, deduplicated, preserving order.
//
// Casdoor's legacy lineage stores phones in at least these forms (we have
// seen all of them in production tables — never normalized at write):
//   - "+19137779708"   (E.164)
//   - "19137779708"    (E.164 minus '+')
//   - "9137779708"     (national without country code, US)
//   - "913-777-9708"   (formatted national, US)
//   - "913 777 9708"   (space-separated)
//   - "(913) 777-9708" (parenthesized US)
//
// We accept ANY of those as input and emit a candidate list that hits
// every column form. We also include util.GetSeperatedPhone (the existing
// helper that strips the leading '+' and parses via libphonenumber).
//
// Edge cases covered:
//   - Leading '+' stripped/added
//   - Leading '1' on 11-digit US numbers stripped to 10-digit national
//   - All non-digit characters stripped
//   - Empty / whitespace-only → empty candidate list (caller short-circuits)
func phoneCandidates(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	seen := map[string]struct{}{}
	out := []string{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	// 1. Raw as given (matches the literal stored form if the writer
	//    happened to dump exactly what the user typed).
	add(raw)

	// 2. libphonenumber-routed normalization (strips '+', emits national
	//    number for any parseable input; passes through unchanged
	//    otherwise). This is the helper that the user-table writer uses
	//    in GetUserByPhone, so a row stored via the standard path will
	//    have this form.
	add(util.GetSeperatedPhone(raw))

	// 3. Digits-only (strips '+', '-', '(', ')', ' ', '.', and anything
	//    else that isn't 0-9). Matches "(913) 777-9708" → "9137779708".
	digits := digitsOnly.ReplaceAllString(raw, "")
	add(digits)

	// 4. E.164 with '+' prefix when we have a plausible international
	//    digit count (10..15). Matches "+19137779708".
	if len(digits) >= 10 && len(digits) <= 15 {
		add("+" + digits)
	}

	// 5. US country-code peel: 11-digit starting with '1' → 10-digit
	//    national. Hits the "9137779708" stored form when the caller
	//    sent "+1 913 777 9708" or "19137779708".
	if len(digits) == 11 && strings.HasPrefix(digits, "1") {
		add(digits[1:])
	}

	// 6. Inverse: 10-digit national → "+1" E.164. Hits the "+19137779708"
	//    stored form when the caller sent "913-777-9708".
	if len(digits) == 10 {
		add("+1" + digits)
		add("1" + digits)
	}

	return out
}

// auditRequestUri is the SANITIZED RequestUri persisted to the audit row.
// We deliberately strip the query string before persistence — the parent
// pipeline at object/record.go::NewRecord captures the full RequestURI,
// which on this endpoint would include `?phone=+19137779708&email=...`,
// i.e. the very PII the threat model promises never to persist. The
// path itself is the only identifying information we need in the audit
// trail; the *value* probed is captured indirectly through
// (attribute-type, result-count) on the Object field.
const auditRequestUri = "/v1/iam/users/by-attribute"

// buildByAttributeAuditRecord constructs the audit Record that will be
// persisted for a single by-attribute probe. Extracted so unit tests can
// assert the EXACT shape that hits the audit table without needing a
// live xorm engine (which object.AddRecord requires).
//
// The two PII-stripping invariants live here:
//   - RequestUri MUST be the bare path; the NewRecord default captures
//     the query string which on THIS endpoint carries the probed value.
//   - Object MUST be empty; NewRecord defaults it to the request body
//     (GET = "") and we never re-populate it with a shape JSON that
//     could trip a future writer into echoing the probed value.
//
// Both invariants are exercised in
// TestAudit_DoesNotPersistProbedValues.
func buildByAttributeAuditRecord(ctx *ApiController, callerClient, callerOrg, attrType string, resultCount, statusCode int, reason string) (*object.Record, error) {
	rec, err := object.NewRecord(ctx.Ctx)
	if err != nil {
		return nil, err
	}
	rec.Organization = callerOrg
	rec.User = callerClient
	rec.Action = "users/by-attribute"
	rec.StatusCode = statusCode
	// CRITICAL: overwrite the RequestUri set by NewRecord. The default
	// captures `ctx.Request.RequestURI` which includes the query string —
	// for THIS endpoint that means the probed phone/email value would be
	// persisted to the audit table, defeating the whole "never log the
	// probed value" defense. Path only, no query string.
	rec.RequestUri = auditRequestUri
	// Object MUST stay empty. NewRecord defaults Object to the request
	// body (GET requests have none, so the default is ""). We intentionally
	// do NOT serialize {attribute, resultCount, reason} into Object — that
	// would create a second persistence path adjacent to the RequestUri
	// fix above. The shape information lives in Response (which is
	// derived, not request-supplied) and Action.
	rec.Object = ""
	// Response carries the shape — derived from server-side state, never
	// from a request-supplied value. Encodes {attribute-type, count,
	// reason, status}. attribute-type is a closed enum ("phone"|"email"|"")
	// not user-controlled text; reason is set by the handler itself.
	rec.Response = "{status:\"" + statusOf(statusCode) +
		"\", attribute:\"" + attrType +
		"\", count:" + itoa(resultCount) +
		", reason:\"" + escapeRecordString(reason) + "\"}"
	return rec, nil
}

// defaultAuditByAttributeProbe writes an Object-level audit row via the
// existing records pipeline. We do NOT include the probed phone/email
// value (that would re-create the enumeration oracle inside our own
// audit table). We include caller, IP, attribute TYPE, and result count.
//
// Bound to byAttrAudit at package init. Tests override the seam.
func defaultAuditByAttributeProbe(ctx *ApiController, callerClient, callerOrg, attrType string, resultCount, statusCode int, reason string) {
	rec, err := buildByAttributeAuditRecord(ctx, callerClient, callerOrg, attrType, resultCount, statusCode, reason)
	if err != nil {
		// Best-effort. Audit failure must not block the response.
		logs.Warning("by-attribute: audit NewRecord failed: %v", err)
		return
	}

	util.SafeGoroutine(func() {
		object.AddRecord(rec)
	})
}

func statusOf(code int) string {
	if code >= 200 && code < 300 {
		return "ok"
	}
	return "error"
}

func itoa(n int) string {
	// Local helper to avoid importing strconv just for this — keeps
	// the audit hot path tight.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func escapeRecordString(s string) string {
	// Minimal JSON-string escape for the audit field — we never trust the
	// reason text to be ASCII-only.
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", " ", "\r", " ")
	return r.Replace(s)
}

// extractBearerJWT pulls the Bearer token off the Authorization header.
// Returns "" if absent or malformed. Does NOT validate the token; that's
// done downstream by ParseJwtTokenByApplication.
func (c *ApiController) extractBearerJWT() string {
	auth := c.Ctx.Input.Header("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	tok := strings.TrimPrefix(auth, "Bearer ")
	// Must look like a 3-part JWT with a non-empty signature.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[2] == "" {
		return ""
	}
	return tok
}

// defaultResolveServiceClaims verifies the incoming Bearer JWT and
// asserts that it was minted via the client_credentials grant. Returns
// the (clientId, owner) on success. The signinMethod / user.Type
// combination is the only reliable client_credentials signal — both
// authorization_code AND password grants produce a "normal-user"
// user.Type, while client_credentials produces the synthetic application
// "user" with Type="application" (object/token_oauth.go:1048).
//
// Bound to byAttrResolveClaims at package init. Tests override the seam.
//
// Returns:
//   - clientId, owner, true: valid client_credentials JWT
//   - "", "", false:        anon (no token), user JWT, expired, or signature
//                            invalid. Caller decides 401 vs 403 by
//                            inspecting `anon`.
func defaultResolveServiceClaims(c *ApiController) (clientId, owner string, anon, ok bool) {
	tok := c.extractBearerJWT()
	if tok == "" {
		return "", "", true, false
	}

	// Look up the token record to find which application minted it.
	rec, err := object.GetTokenByAccessToken(tok)
	if err != nil || rec == nil {
		// Signature might still verify later, but without a token record
		// we cannot match it to an application certificate. Treat as
		// anon (401).
		return "", "", true, false
	}

	// Token.Application stores the bare application name (see
	// object/token_oauth.go:247 et al), and Token.Organization stores
	// its owner. Compose the owner/name id directly — GetApplication
	// parses via util.GetOwnerAndNameFromIdWithError which requires the
	// two-token form. The mcpself/authz_filter call sites that bare-name
	// it work only for system apps; we must support tenant apps
	// (liquidity-bd, liquidity-ats, liquidity-ta) which live under the
	// tenant org.
	appOwner := rec.Organization
	if appOwner == "" {
		// Fall back to Owner field, which is what xorm reads as pk.
		appOwner = rec.Owner
	}
	if appOwner == "" {
		return "", "", true, false
	}
	app, err := object.GetApplication(appOwner + "/" + rec.Application)
	if err != nil || app == nil {
		return "", "", true, false
	}

	claims, err := object.ParseJwtTokenByApplication(tok, app)
	if err != nil || claims == nil || claims.User == nil {
		return "", "", true, false
	}

	// Reject expired tokens (the JWT library checks `exp` but we
	// double-check the token-record expiry which is the canonical source
	// of truth — JWTs can be in-flight after revocation).
	if isExpired, _ := util.IsTokenExpired(rec.CreatedTime, rec.ExpiresIn); isExpired {
		return "", "", true, false
	}

	// **The discriminator**: client_credentials mints a synthetic
	// application-user with a specific shape (see GetClientCredentialsToken
	// at object/token_oauth.go:1044-1049):
	//
	//   nullUser := &User{
	//     Owner: application.Owner,
	//     Id:    application.GetId(),
	//     Name:  application.Name,   <-- KEY: name === app.name
	//     Type:  "application",      <-- forgeable on its own
	//   }
	//
	// And the JWT is generated via generateJwtToken(app, nullUser, "", "", "", scope, "", host) —
	// the three empty strings are provider, providerType, signinMethod.
	// So a *true* client_credentials claim has:
	//   Type         == "application"
	//   User.Name    == application.Name  (the registered ClientId is by
	//                                       construction the app's name)
	//   Provider     == ""
	//   SigninMethod == ""
	//
	// User.Type ALONE is NOT sufficient: AddUser/UpdateUser persist
	// arbitrary Type from the request body (object/user.go:928,934), so a
	// tenant admin can create a user with Type="application", set a
	// password, password-grant a JWT, and pass the bare Type discriminator.
	// We now require ALL FOUR fields to match. The strongest is
	// `claims.User.Name == app.Name` — a tenant-admin-promoted user can
	// never have `name == app.name` without also owning the matching
	// application name in the same org (which is the same as owning the
	// client_credentials secret in the first place).
	if claims.User.Type != "application" {
		return "", "", false, false
	}
	if claims.User.Name != app.Name {
		// A user JWT carrying Type="application" but whose user-name
		// differs from the application name is the exact forgery shape.
		return "", "", false, false
	}
	if claims.Provider != "" {
		// client_credentials never has a Provider (no IdP involved).
		// password / authorization_code grants do.
		return "", "", false, false
	}
	if claims.SigninMethod != "" {
		// client_credentials never has a SigninMethod (it's not a
		// sign-in). Password / OIDC / WebAuthn etc. all set this.
		return "", "", false, false
	}

	// clientId == the registered Azp (== application.ClientId). Fall
	// back to the token record's Application name if Azp is somehow
	// empty (legacy tokens).
	clientId = claims.Azp
	if clientId == "" {
		clientId = app.ClientId
	}

	// owner == the JWT-bound org. For client_credentials, this is the
	// application's own org (set as nullUser.Owner = application.Owner).
	owner = claims.User.Owner
	if owner == "" {
		owner = app.Organization
	}

	return clientId, owner, false, true
}

// GetUsersByAttribute
// @Title GetUsersByAttribute
// @Tag User API
// @Description Server-to-server soft-signal lookup: does a user row with
// this phone/email exist in MY org? Auth: client_credentials JWT only.
// User JWTs (authorization_code/password) are rejected with 403.
// @Param phone query string false "phone in any common form"
// @Param email query string false "email"
// @Success 200 {object} controllers.Response 200 with possibly-empty array
// @router /users/by-attribute [get]
func (c *ApiController) GetUsersByAttribute() {
	// (1) Auth: must be a client_credentials JWT.
	clientId, owner, anon, ok := byAttrResolveClaims(c)
	if !ok {
		if anon {
			c.Ctx.Output.SetStatus(http.StatusUnauthorized)
			c.ResponseError("unauthorized: server-to-server JWT required")
			return
		}
		c.Ctx.Output.SetStatus(http.StatusForbidden)
		c.ResponseError("forbidden: server-to-server credentials required")
		return
	}

	// (2) Allowlist: caller's clientId must be explicitly permitted.
	allow := byAttributeAllowedClients()
	if _, permitted := allow[clientId]; !permitted {
		c.Ctx.Output.SetStatus(http.StatusForbidden)
		// Audit the rejection — useful for spotting misconfigured
		// services or stolen credentials being probed.
		byAttrAudit(c, clientId, owner, "", 0, http.StatusForbidden, "client not in allowlist")
		c.ResponseError("forbidden: client not authorized for users/by-attribute")
		return
	}

	// (3) Rate limit: 10/min per clientId. IP is deliberately NOT in the
	//     key — XFF is client-controlled at this layer (ingress does not
	//     pin trustedIPs as of the version pinned in universe), so an
	//     IP-keyed limiter is bypassable by header rotation. clientId
	//     alone is sufficient because the caller cannot rotate it without
	//     owning another allowlisted service credential. IP-based limits
	//     belong at the ingress layer and are tracked as a follow-up.
	if !byAttributeRateLimit(clientId) {
		c.Ctx.Output.SetStatus(http.StatusTooManyRequests)
		byAttrAudit(c, clientId, owner, "", 0, http.StatusTooManyRequests, "rate limit exceeded")
		c.ResponseError("too many requests")
		return
	}

	// (4) Org scope: read from JWT. Any `owner=` query param is IGNORED.
	//     Reject explicit cross-org attempts with 403 — silent ignore
	//     would let a curious caller think they're getting cross-org
	//     data when they aren't.
	if reqOwner := c.Ctx.Input.Query("owner"); reqOwner != "" && reqOwner != owner {
		c.Ctx.Output.SetStatus(http.StatusForbidden)
		byAttrAudit(c, clientId, owner, "", 0, http.StatusForbidden, "cross-org owner override attempted")
		c.ResponseError("forbidden: owner is bound to the caller's JWT")
		return
	}

	// (5) Read inputs.
	phone := strings.TrimSpace(c.Ctx.Input.Query("phone"))
	email := strings.TrimSpace(c.Ctx.Input.Query("email"))

	if phone == "" && email == "" {
		c.Ctx.Output.SetStatus(http.StatusBadRequest)
		byAttrAudit(c, clientId, owner, "", 0, http.StatusBadRequest, "missing attribute")
		c.ResponseError("provide one of: phone, email")
		return
	}
	if phone != "" && email != "" {
		c.Ctx.Output.SetStatus(http.StatusBadRequest)
		byAttrAudit(c, clientId, owner, "", 0, http.StatusBadRequest, "exactly one attribute required")
		c.ResponseError("provide exactly one of: phone, email")
		return
	}

	attrType := "phone"
	if email != "" {
		attrType = "email"
	}

	// (6) Lookup.
	out := []*UserByAttribute{}
	seen := map[string]struct{}{}

	switch attrType {
	case "email":
		// Email lookup is single-shot: emails are normalized on write
		// (lowercased) so the field is canonical. Use GetUserByEmail
		// which scopes by owner.
		u, err := object.GetUserByEmail(owner, strings.ToLower(email))
		if err != nil {
			logs.Warning("by-attribute: email lookup err: %v", err)
			c.Ctx.Output.SetStatus(http.StatusInternalServerError)
			byAttrAudit(c, clientId, owner, attrType, 0, http.StatusInternalServerError, "lookup error")
			c.ResponseError("internal error")
			return
		}
		if u != nil && !u.IsDeleted {
			out = append(out, projectUserForByAttribute(u))
		}

	case "phone":
		// Phone is the ugly case: stored inconsistently. Probe every
		// reasonable variant. Owner-scoped via GetUserByPhone (which
		// also routes through util.GetSeperatedPhone). We deduplicate
		// by (owner,name) so the same row found via two candidate
		// forms only appears once.
		for _, cand := range phoneCandidates(phone) {
			if len(out) >= byAttributeMaxResults {
				break
			}
			u, err := object.GetUserByPhone(owner, cand)
			if err != nil {
				logs.Warning("by-attribute: phone lookup err for cand=%q: %v", cand, err)
				continue
			}
			if u == nil || u.IsDeleted {
				continue
			}
			key := u.Owner + "/" + u.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, projectUserForByAttribute(u))
		}
	}

	// (7) Audit the hit/miss.
	byAttrAudit(c, clientId, owner, attrType, len(out), http.StatusOK, "")

	// (8) Respond. ALWAYS 200, even on miss — this is the soft-signal
	//     contract. A miss must be indistinguishable in HTTP status from
	//     a hit; only the body differs.
	c.ResponseOk(out, map[string]int{
		"total": len(out),
		"max":   byAttributeMaxResults,
	})
}

// projectUserForByAttribute is the deliberate field whitelist for the
// soft-signal response. We pick the minimum set of fields a server-to-
// server caller needs to identify "is this the right person?": id, name,
// owner, email, phone, displayName, createdTime. We OMIT password,
// passwordSalt, passwordType, totp, webauthn credentials, addresses,
// idCard, dateOfBirth, externalId, and the entire properties map — none
// of those are needed for the soft-signal use case and several are
// PII/secret-bearing.
func projectUserForByAttribute(u *object.User) *UserByAttribute {
	if u == nil {
		return nil
	}
	return &UserByAttribute{
		Id:          u.Id,
		Owner:       u.Owner,
		Name:        u.Name,
		Email:       u.Email,
		Phone:       u.Phone,
		DisplayName: u.DisplayName,
		CreatedTime: u.CreatedTime,
	}
}

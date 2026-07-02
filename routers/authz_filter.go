// Copyright 2025 Hanzo AI, Inc.
// Portions Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

package routers

import (
	stdcontext "context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hanzoai/beego/v2/core/logs"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/controllers"
	"github.com/hanzoai/iam/object"

	"github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/iam/authz"
	"github.com/hanzoai/iam/util"
)

// getUsernameFromBearerToken extracts the user identity from a JWT Bearer token
// after verifying the token signature via the application's certificate.
// This enables stateless API calls (e.g., from backend services forwarding user tokens)
// without requiring an active IAM session.
func getUsernameFromBearerToken(ctx *context.Context) string {
	auth := ctx.Input.Header("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	tokenString := strings.TrimPrefix(auth, "Bearer ")

	// Reject malformed tokens (must have 3 dot-separated parts with non-empty signature).
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 || parts[2] == "" {
		return ""
	}

	// Look up the token record to find its application, then verify the
	// JWT signature using the application's certificate — same pattern as
	// mcpself/auth.go:GetClaimsFromToken.
	tokenRecord, err := object.GetTokenByAccessToken(tokenString)
	if err != nil || tokenRecord == nil {
		logs.Warning("getUsernameFromBearerToken: token lookup failed: %v", err)
		return ""
	}

	// Resolve the application that minted this token. Token.Application stores the
	// BARE app name (see object/token_oauth.go); its owner is the Casdoor
	// maintainer namespace (conf.AdminOrg == "admin" for every platform app),
	// while Token.Organization is the TENANT slug — for an admin-owned platform
	// app (hanzo-console, hanzo-cloud, …) the two DIFFER (owner=admin,
	// organization=hanzo). Composing organization/name therefore points at a
	// non-existent "hanzo/hanzo-console" row, so the app never resolves to its
	// real admin-owned record and the client_credentials discriminator below
	// never fires. FindApplicationByName is the canonical resolver for exactly
	// this: it tries the tenant org, then conf.AdminOrg, then a global by-name
	// lookup — the one and only way to resolve an app from a bare name + org hint.
	application, err := object.FindApplicationByName(tokenRecord.Application, tokenRecord.Organization)
	if err != nil || application == nil {
		logs.Warning("getUsernameFromBearerToken: application lookup failed for name=%q orgHint=%q owner=%q: %v", tokenRecord.Application, tokenRecord.Organization, tokenRecord.Owner, err)
		return ""
	}

	claims, err := object.ParseJwtTokenByApplication(tokenString, application)
	if err != nil {
		logs.Warning("getUsernameFromBearerToken: JWT verification failed: %v", err)
		return ""
	}

	// A confidential-client (client_credentials) JWT resolves to the canonical
	// "app/<name>" subject via the ONE shared rule (confidentialClientSubject) —
	// the same subject the Basic-auth transport (routers/base.go
	// getUsernameByClientIdSecret) and the AutoSigninFilter session seed produce,
	// so every "app/<name>"-keyed control (authz app short-circuit, IsAppUser,
	// per-capability allowlists, R-1 non-global-admin downgrade) applies uniformly
	// regardless of transport.
	if sub, isCC := confidentialClientSubject(claims, application); isCC {
		return sub
	}

	// Human user JWT (authorization_code / password): resolve to <owner>/<name>.
	if claims.User != nil && claims.User.Owner != "" && claims.User.Name != "" {
		return fmt.Sprintf("%s/%s", claims.User.Owner, claims.User.Name)
	}
	return ""
}

// confidentialClientSubject is the ONE canonical rule mapping a VERIFIED
// client_credentials confidential-client JWT to its authz subject. It is shared
// by getUsernameFromBearerToken (ApiFilter) and AutoSigninFilter — the latter
// runs first and seeds the session, so BOTH transports must agree or the
// normalization is silently bypassed (the SA-keystone bug).
//
//   - Not a confidential-client token (human user JWT): returns ("", false) so
//     the caller keeps its <owner>/<name> resolution unchanged.
//   - Genuine confidential-client token: returns isCC=true and subject
//     "app/<name>". Fail-secure Red#4 reservation guard — a capability-reserved
//     name is legitimate ONLY on the admin-owned platform app; on any other
//     owner it returns ("", true) so the caller treats the request as anonymous,
//     NEVER as the (non-privileged but non-anonymous) human <org>/<app> form,
//     closing the "register <theirOrg>/hanzo-console then client_credentials-
//     grant" cross-tenant escalation.
func confidentialClientSubject(claims *object.Claims, application *object.Application) (subject string, isCC bool) {
	if !object.IsClientCredentialsClaim(claims, application) {
		return "", false
	}
	if application.Owner != conf.AdminOrg && object.AppNameIsCapabilityReserved(application.Name) {
		logs.Warning("confidentialClientSubject: reserved app name %q on non-admin owner %q — refused", application.Name, application.Owner)
		return "", true
	}
	return "app/" + application.Name, true
}

// isOrgAppManagementRoute returns true for organization and application read
// endpoints that authenticated users should be able to access without authz
// evaluation. Mutation routes (add/update/delete) are NOT bypassed — they
// must pass through the authz enforcer to prevent privilege escalation.
//
// SECURITY (Red H-5): the single-application read (get-application) is
// DELIBERATELY excluded from this bypass. It returns one specific app keyed by
// `id=<org>/<name>`, so bypassing authz let any authenticated user fetch
// another org's application config cross-tenant. It now falls through to
// authz.IsAllowed, which scopes by the object owner (own org or the admin org)
// — a non-owner is denied. The plural/org reads stay bypassed: they are broad,
// always masked (GetMaskedApplications), and needed for multi-tenant onboarding.
func isOrgAppManagementRoute(method, urlPath string) bool {
	if method != "GET" {
		return false
	}
	switch urlPath {
	case "/v1/iam/get-organizations", "/v1/iam/get-organization",
		"/v1/iam/get-applications":
		return true
	}
	return false
}

// isProjectManagementRoute reports whether the request targets a project
// CRUD/read endpoint. Any authenticated user may manage projects (e.g. create
// their first project during registration), the same posture as org/app CRUD;
// the IsAdmin-based Casbin path is unreliable here (xorm bool deserialization),
// the same rationale as isOrgAppManagementRoute above.
func isProjectManagementRoute(method, urlPath string) bool {
	switch urlPath {
	case "/v1/iam/add-project", "/v1/iam/update-project", "/v1/iam/delete-project":
		return method == "POST"
	case "/v1/iam/get-projects", "/v1/iam/get-project", "/v1/iam/get-organization-projects":
		return method == "GET"
	}
	return false
}

// isByAttributeRoute is the server-to-server soft-signal lookup. Auth is
// enforced by the controller itself (client_credentials JWT + env
// allowlist + per-(clientId,IP) rate limit), so the generic authz engine
// must not deny anonymous traffic here. The handler returns 401 on missing
// JWT and 403 on user-grant or non-allowlisted JWTs — full coverage lives
// in controllers/users_by_attribute.go.
func isByAttributeRoute(method, urlPath string) bool {
	return method == "GET" && urlPath == "/v1/iam/users/by-attribute"
}

type Object struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type ObjectWithOrg struct {
	Object
	Organization string `json:"organization"`
}

func getUsername(ctx *context.Context) (username string) {
	username, ok := ctx.Input.Session("username").(string)
	if !ok || username == "" {
		username, _ = getUsernameByClientIdSecret(ctx)
	}

	// If no session/client credentials, try Bearer token (JWT) authentication.
	// This allows stateless API calls with valid IAM access tokens.
	if username == "" {
		username = getUsernameFromBearerToken(ctx)
	}

	session := ctx.Input.Session("SessionData")
	if session == nil {
		return
	}

	sessionData := &controllers.SessionData{}
	err := util.JsonToStruct(session.(string), sessionData)
	if err != nil {
		logs.Error("GetSessionData failed, error: %s", err)
		return ""
	}

	if sessionData.ExpireTime != 0 &&
		sessionData.ExpireTime < time.Now().Unix() {
		err = ctx.Input.CruSession.Set(stdcontext.Background(), "username", "")
		if err != nil {
			logs.Error("Failed to clear expired session, error: %s", err)
			return ""
		}
		err = ctx.Input.CruSession.Delete(stdcontext.Background(), "SessionData")
		if err != nil {
			logs.Error("Failed to clear expired session, error: %s", err)
		}
		return ""
	}

	return
}

func getSubject(ctx *context.Context) (string, string) {
	username := getUsername(ctx)
	if username == "" {
		return "anonymous", "anonymous"
	}

	// username == "hanzo/z"
	owner, name, err := util.GetOwnerAndNameFromIdWithError(username)
	if err != nil {
		panic(err)
	}
	return owner, name
}

func getObject(ctx *context.Context) (string, string, error) {
	method := ctx.Request.Method
	path := ctx.Request.URL.Path

	// Special handling for MCP requests
	if path == "/v1/iam/mcp" && method == http.MethodPost {
		return getMcpObject(ctx)
	}

	if strings.HasPrefix(path, "/v1/iam/server/") {
		return ctx.Input.Param(":owner"), ctx.Input.Param(":name"), nil
	}

	if method == http.MethodGet {
		if ctx.Request.URL.Path == "/v1/iam/get-policies" {
			if ctx.Input.Query("id") == "/" {
				adapterId := ctx.Input.Query("adapterId")
				if adapterId != "" {
					return util.GetOwnerAndNameFromIdWithError(adapterId)
				}
			} else {
				// query == "?id=superuser/admin"
				id := ctx.Input.Query("id")
				if id != "" {
					return util.GetOwnerAndNameFromIdWithError(id)
				}
			}
		}

		if !(strings.HasPrefix(ctx.Request.URL.Path, "/v1/iam/get-") && strings.HasSuffix(ctx.Request.URL.Path, "s")) {
			// query == "?id=superuser/admin"
			id := ctx.Input.Query("id")
			if id != "" {
				return util.GetOwnerAndNameFromIdWithError(id)
			}
		}

		owner := ctx.Input.Query("owner")
		if owner != "" {
			return owner, "", nil
		}

		return "", "", nil
	} else {
		if path == "/v1/iam/add-policy" || path == "/v1/iam/remove-policy" || path == "/v1/iam/update-policy" || path == "/v1/iam/send-invitation" {
			id := ctx.Input.Query("id")
			if id != "" {
				return util.GetOwnerAndNameFromIdWithError(id)
			}
		}

		body := ctx.Input.RequestBody
		if len(body) == 0 {
			return ctx.Request.Form.Get("owner"), ctx.Request.Form.Get("name"), nil
		}

		var obj Object

		if strings.HasSuffix(path, "-application") || strings.HasSuffix(path, "-token") ||
			strings.HasSuffix(path, "-syncer") || strings.HasSuffix(path, "-webhook") {
			var objWithOrg ObjectWithOrg
			err := json.Unmarshal(body, &objWithOrg)
			if err != nil {
				return "", "", nil
			}
			return objWithOrg.Organization, objWithOrg.Name, nil
		}

		err := json.Unmarshal(body, &obj)
		if err != nil {
			// this is not error
			return "", "", nil
		}

		if strings.HasSuffix(path, "-organization") {
			// Organization operations: use owner field (typically "admin") as the
			// resource owner so that org admins (isAdmin=true) can create/update/delete
			// organizations. Previously used obj.Name which made objOwner the new org's
			// name — causing authorization to fail for non-superuser users.
			return obj.Owner, obj.Name, nil
		}

		if path == "/v1/iam/delete-resource" {
			tokens := strings.Split(obj.Name, "/")
			if len(tokens) >= 5 {
				obj.Name = tokens[4]
			}
		}

		return obj.Owner, obj.Name, nil
	}
}

func willLog(subOwner string, subName string, method string, urlPath string, objOwner string, objName string) bool {
	if subOwner == "anonymous" && subName == "anonymous" && method == "GET" && (urlPath == "/v1/iam/get-account" || urlPath == "/v1/iam/get-app-login") && objOwner == "" && objName == "" {
		return false
	}
	return true
}

func getUrlPath(ctx *context.Context) string {
	urlPath := ctx.Request.URL.Path

	if strings.HasPrefix(urlPath, "/cas") && (strings.HasSuffix(urlPath, "/serviceValidate") || strings.HasSuffix(urlPath, "/proxy") || strings.HasSuffix(urlPath, "/proxyValidate") || strings.HasSuffix(urlPath, "/validate") || strings.HasSuffix(urlPath, "/p3/serviceValidate") || strings.HasSuffix(urlPath, "/p3/proxyValidate") || strings.HasSuffix(urlPath, "/samlValidate")) {
		return "/cas"
	}

	if strings.HasPrefix(urlPath, "/scim") {
		return "/scim"
	}

	// /login/oauth/* — Casdoor-legacy OAuth surface. Both the bare prefix
	// (e.g. /login/oauth/access_token) and the canonical /v1/iam/-prefixed
	// variant (e.g. /v1/iam/login/oauth/access_token) collapse to the same
	// /login/oauth resource so the anonymous policy applies. Without the
	// /v1/iam/login/oauth case, IAM v1.13.0+ public clients hit
	// "Unauthorized operation" because Casbin sees the full prefixed path.
	if strings.HasPrefix(urlPath, "/login/oauth") ||
		strings.HasPrefix(urlPath, "/v1/iam/login/oauth") {
		return "/login/oauth"
	}

	// OAuth surface: collapse the canonical /v1/iam/oauth/* paths to the
	// authz resource keys the anonymous OIDC/OAuth policy already grants.
	// /v1/iam/oauth/authorize must be anonymous-reachable — the handler
	// 302s to the SPA login at /login/oauth/authorize, and a denial here
	// surfaces as `{status:"error",msg:"Unauthorized operation"}` before
	// the redirect can run.
	switch urlPath {
	// TODO(red-2026-04-30,finding-C): introspect and revoke share the
	// anonymous /login/oauth policy so the OIDC metadata endpoints work,
	// but introspect leaks a token-validity oracle and revoke is a free
	// unauthenticated mutation. Re-evaluate post-demo: split these out
	// and require client_credentials (RFC 7662 §2.1, RFC 7009 §2.1).
	case "/v1/iam/oauth/authorize", "/v1/iam/oauth/token", "/v1/iam/oauth/access_token",
		"/v1/iam/oauth/refresh", "/v1/iam/oauth/refresh_token",
		"/v1/iam/oauth/introspect", "/v1/iam/oauth/revoke", "/v1/iam/oauth/register":
		return "/login/oauth"
	case "/v1/iam/oauth/userinfo":
		return "/v1/iam/userinfo"
	case "/v1/iam/oauth/device":
		return "/v1/iam/device-auth"
	case "/v1/iam/oauth/logout":
		return "/v1/iam/logout"
	}

	if strings.HasPrefix(urlPath, "/v1/iam/webauthn") {
		return "/v1/iam/webauthn"
	}

	// /v1/iam/web3/* — multi-chain wallet Sign-In-With-X (@luxwallet/connect).
	// Both endpoints MUST be anonymous-reachable: the nonce is minted BEFORE any
	// token exists, and verify IS the login (it mints the session/JWT). Phishing
	// safety rides on the request-host-derived domain bound into the signed
	// CAIP-122 message + the single-use nonce burn, not on a pre-existing grant.
	// Without this, the authz engine default-denies the unmapped path and the
	// wallet flow returns `{status:"error",msg:"Unauthorized operation"}` before
	// the handler runs (same failure mode the /login/oauth case fixed).
	if strings.HasPrefix(urlPath, "/v1/iam/web3") {
		return "/login/oauth"
	}

	if strings.HasPrefix(urlPath, "/v1/iam/saml/redirect") {
		return "/v1/iam/saml/redirect"
	}

	return urlPath
}

func getExtraInfo(ctx *context.Context, urlPath string) map[string]interface{} {
	var extra map[string]interface{}
	if urlPath == "/v1/iam/mcp" {
		var m map[string]interface{}
		if err := json.Unmarshal(ctx.Input.RequestBody, &m); err != nil {
			return nil
		}

		method, ok := m["method"].(string)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			"detailPathUrl": method,
		}
	}
	return extra
}

func getImpersonateUser(ctx *context.Context, subOwner, subName, username string) (string, string, string) {
	impersonateUser, ok := ctx.Input.Session("impersonateUser").(string)
	impersonateUserCookie := ctx.GetCookie("impersonateUser")
	if ok && impersonateUser != "" && impersonateUserCookie != "" {
		user, err := object.GetUser(util.GetId(subOwner, subName))
		if err != nil {
			panic(err)
		}

		if user != nil {
			impUserOwner, impUserName, err := util.GetOwnerAndNameFromIdWithError(impersonateUser)
			if err != nil {
				panic(err)
			}

			if user.IsAdmin && impUserOwner == user.Owner {
				ctx.Input.SetData("impersonating", true)
				return impUserOwner, impUserName, impersonateUser
			}
		}
	}

	return subOwner, subName, username
}

func ApiFilter(ctx *context.Context) {
	// Recover from panics (e.g. database unreachable) and return a proper
	// JSON error instead of beego's default plain-text panic handler.
	defer func() {
		if r := recover(); r != nil {
			errMsg := fmt.Sprintf("%v", r)
			logs.Error("ApiFilter panic recovered: %s", errMsg)
			responseError(ctx, errMsg)
		}
	}()

	method := ctx.Request.Method
	urlPath := getUrlPath(ctx)

	// Health probes — always allow, no auth required.
	// Wired in every shape so probes are interchangeable: /healthz, /health,
	// /v1/iam/healthz, /v1/iam/health.
	if method == "GET" {
		switch urlPath {
		case "/healthz", "/health", "/v1/iam/healthz", "/v1/iam/health":
			return
		}
	}

	if isServiceTokenAuthenticated(ctx) && isServiceTokenRoute(urlPath) {
		ctx.Input.SetData("currentUserId", "service/token")
		logLine := fmt.Sprintf("subOwner = service, subName = token, method = %s, urlPath = %s, obj.Owner = , obj.Name = , result = allow", method, urlPath)
		fmt.Println(logLine)
		util.LogInfo(ctx, logLine)
		return
	}

	// Server-to-server soft-signal route. Controller does the full auth
	// dance (client_credentials JWT discriminator + env allowlist +
	// per-(clientId,IP) rate limit). The generic authz engine has no
	// useful policy here and would deny anonymous traffic at the wire —
	// but we want anonymous traffic to reach the controller so it can
	// return the right shape (401 with WWW-Authenticate vs 403 vs 429
	// vs 200). Bypass with NO subject set; the handler reads the
	// Authorization header directly.
	if isByAttributeRoute(method, urlPath) {
		logLine := fmt.Sprintf("subOwner = -, subName = -, method = %s, urlPath = %s, result = allow (by-attribute controller-enforced)",
			method, urlPath)
		fmt.Println(logLine)
		util.LogInfo(ctx, logLine)
		return
	}

	subOwner, subName := getSubject(ctx)

	// Allow authenticated (non-anonymous) users to manage organizations and
	// applications. These operations are essential for multi-tenant workflows
	// where org admins create/manage orgs from frontend apps via Bearer token.
	// The authz enforcer has matching policies, but xorm boolean deserialization
	// issues can cause the user.IsAdmin check to fail. This bypass ensures
	// org/app CRUD works reliably for any authenticated user.
	if subOwner != "anonymous" && subName != "anonymous" {
		if isOrgAppManagementRoute(method, urlPath) {
			username := fmt.Sprintf("%s/%s", subOwner, subName)
			ctx.Input.SetData("currentUserId", username)
			logLine := fmt.Sprintf("subOwner = %s, subName = %s, method = %s, urlPath = %s, result = allow (org/app management bypass)",
				subOwner, subName, method, urlPath)
			fmt.Println(logLine)
			util.LogInfo(ctx, logLine)
			return
		}
	}
	// Allow any authenticated user to create/manage projects (e.g. create their
	// first project during registration) — same posture as the org/app bypass
	// above. NOTE: projects created via the onboarding currently target the
	// shared "hanzo" org; per-tenant org creation is the follow-up.
	if subOwner != "anonymous" && subName != "anonymous" {
		if isProjectManagementRoute(method, urlPath) {
			username := fmt.Sprintf("%s/%s", subOwner, subName)
			ctx.Input.SetData("currentUserId", username)
			logLine := fmt.Sprintf("subOwner = %s, subName = %s, method = %s, urlPath = %s, result = allow (project management bypass)",
				subOwner, subName, method, urlPath)
			fmt.Println(logLine)
			util.LogInfo(ctx, logLine)
			return
		}
	}
	// stash current user info into request context for controllers
	username := ""
	if !(subOwner == "anonymous" && subName == "anonymous") {
		username = fmt.Sprintf("%s/%s", subOwner, subName)
		subOwner, subName, username = getImpersonateUser(ctx, subOwner, subName, username)
	}
	ctx.Input.SetData("currentUserId", username)

	extraInfo := getExtraInfo(ctx, urlPath)

	objOwner, objName := "", ""
	if urlPath != "/v1/iam/get-app-login" && urlPath != "/v1/iam/get-resource" {
		var err error
		objOwner, objName, err = getObject(ctx)
		if err != nil {
			responseError(ctx, err.Error())
			return
		}
	}

	if strings.HasPrefix(urlPath, "/v1/iam/notify-payment") {
		urlPath = "/v1/iam/notify-payment"
	}

	isAllowed := authz.IsAllowed(subOwner, subName, method, urlPath, objOwner, objName, extraInfo)

	result := "deny"
	if isAllowed {
		result = "allow"
	}

	if willLog(subOwner, subName, method, urlPath, objOwner, objName) {
		logLine := fmt.Sprintf("subOwner = %s, subName = %s, method = %s, urlPath = %s, obj.Owner = %s, obj.Name = %s, result = %s",
			subOwner, subName, method, urlPath, objOwner, objName, result)
		extra := formatExtraInfo(extraInfo)
		if extra != "" {
			logLine += fmt.Sprintf(", extraInfo = %s", extra)
		}
		fmt.Println(logLine)
		util.LogInfo(ctx, logLine)
	}

	if !isAllowed {
		if urlPath == "/v1/iam/mcp" || strings.HasPrefix(urlPath, "/v1/iam/server/") {
			denyMcpRequest(ctx)
		} else {
			denyRequest(ctx)
		}
		record, err := object.NewRecord(ctx)
		if err != nil {
			return
		}

		record.Organization = subOwner
		record.User = subName // auth:Unauthorized operation
		record.Response = fmt.Sprintf("{status:\"error\", msg:\"%s\"}", T(ctx, "auth:Unauthorized operation"))

		util.SafeGoroutine(func() {
			object.AddRecord(record)
		})
	}
}

func formatExtraInfo(extra map[string]interface{}) string {
	if extra == nil {
		return ""
	}
	b, err := json.Marshal(extra)
	if err != nil {
		return ""
	}
	return string(b)
}

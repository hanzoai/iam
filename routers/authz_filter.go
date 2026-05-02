// Copyright 2021 The Hanzo Authors. All Rights Reserved.
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

	"github.com/beego/beego/v2/core/logs"
	"github.com/hanzoai/iam/controllers"
	"github.com/hanzoai/iam/object"

	"github.com/beego/beego/v2/server/web/context"
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

	application, err := object.GetApplication(tokenRecord.Application)
	if err != nil || application == nil {
		logs.Warning("getUsernameFromBearerToken: application lookup failed for %s: %v", tokenRecord.Application, err)
		return ""
	}

	claims, err := object.ParseJwtTokenByApplication(tokenString, application)
	if err != nil {
		logs.Warning("getUsernameFromBearerToken: JWT verification failed: %v", err)
		return ""
	}

	if claims.User != nil && claims.User.Owner != "" && claims.User.Name != "" {
		return fmt.Sprintf("%s/%s", claims.User.Owner, claims.User.Name)
	}
	return ""
}

// isOrgAppManagementRoute returns true for organization and application read
// endpoints that authenticated users should be able to access without authz
// evaluation. Mutation routes (add/update/delete) are NOT bypassed — they
// must pass through the authz enforcer to prevent privilege escalation.
func isOrgAppManagementRoute(method, urlPath string) bool {
	if method != "GET" {
		return false
	}
	switch urlPath {
	case "/v1/iam/get-organizations", "/v1/iam/get-organization",
		"/v1/iam/get-applications", "/v1/iam/get-application":
		return true
	}
	return false
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
				// query == "?id=built-in/admin"
				id := ctx.Input.Query("id")
				if id != "" {
					return util.GetOwnerAndNameFromIdWithError(id)
				}
			}
		}

		if !(strings.HasPrefix(ctx.Request.URL.Path, "/v1/iam/get-") && strings.HasSuffix(ctx.Request.URL.Path, "s")) {
			// query == "?id=built-in/admin"
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
			// name — causing authorization to fail for non-built-in users.
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

	// Normalize /oauth/* aliases (and their /v1/iam/-prefixed canonical
	// variants) to existing authz paths so the anonymous OIDC/OAuth policy
	// applies. /oauth/authorize is the OIDC-advertised authorize endpoint;
	// it must be reachable by anonymous users (the Beego handler 302s to the
	// SPA login at /login/oauth/authorize). Without this, authz denies
	// before OAuthAuthorizeRedirect can run and the client sees
	// `{status:"error",msg:"Unauthorized operation"}`.
	switch urlPath {
	// TODO(red-2026-04-30,finding-C): /oauth/introspect and /oauth/revoke
	// are aliased to the anonymous /login/oauth policy here so the OIDC
	// metadata endpoints work, but introspect leaks a token-validity
	// oracle and revoke is a free unauthenticated mutation. Re-evaluate
	// post-demo: split these out and require client_credentials (RFC 7662
	// §2.1, RFC 7009 §2.1) before they hit this normalizer.
	case "/oauth/authorize", "/oauth/token", "/oauth/access_token", "/oauth/refresh", "/oauth/introspect", "/oauth/revoke",
		"/v1/iam/oauth/authorize", "/v1/iam/oauth/token", "/v1/iam/oauth/access_token", "/v1/iam/oauth/refresh", "/v1/iam/oauth/introspect", "/v1/iam/oauth/revoke":
		return "/login/oauth"
	case "/oauth/userinfo", "/v1/iam/oauth/userinfo":
		return "/v1/iam/userinfo"
	case "/oauth/device", "/v1/iam/oauth/device":
		return "/v1/iam/device-auth"
	case "/oauth/logout", "/v1/iam/oauth/logout":
		return "/v1/iam/logout"
	}

	if strings.HasPrefix(urlPath, "/v1/iam/webauthn") {
		return "/v1/iam/webauthn"
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

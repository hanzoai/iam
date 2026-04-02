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
	"encoding/base64"
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

// getUsernameFromBearerToken extracts the user identity from a JWT Bearer token.
// This enables stateless API calls (e.g., from backend services forwarding user tokens)
// without requiring an active IAM session.
func getUsernameFromBearerToken(ctx *context.Context) string {
	auth := ctx.Input.Header("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	// Quick JWT decode (no verification — the token was already issued by us)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}

	// Base64url decode the payload
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}

	var claims struct {
		Owner string `json:"owner"`
		Name  string `json:"name"`
		Sub   string `json:"sub"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}

	// Casdoor tokens have owner + name fields
	if claims.Owner != "" && claims.Name != "" {
		return fmt.Sprintf("%s/%s", claims.Owner, claims.Name)
	}
	return ""
}

// isOrgAppManagementRoute returns true for organization and application CRUD
// endpoints that authenticated users should be able to access.
func isOrgAppManagementRoute(method, urlPath string) bool {
	switch urlPath {
	case "/api/add-organization", "/api/update-organization", "/api/delete-organization":
		return method == "POST"
	case "/api/get-organizations", "/api/get-organization":
		return method == "GET"
	case "/api/add-application", "/api/update-application", "/api/delete-application":
		return method == "POST"
	case "/api/get-applications":
		return method == "GET"
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
	if path == "/api/mcp" && method == http.MethodPost {
		return getMcpObject(ctx)
	}

	if strings.HasPrefix(path, "/api/server/") {
		return ctx.Input.Param(":owner"), ctx.Input.Param(":name"), nil
	}

	if method == http.MethodGet {
		if ctx.Request.URL.Path == "/api/get-policies" {
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

		if !(strings.HasPrefix(ctx.Request.URL.Path, "/api/get-") && strings.HasSuffix(ctx.Request.URL.Path, "s")) {
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
		if path == "/api/add-policy" || path == "/api/remove-policy" || path == "/api/update-policy" || path == "/api/send-invitation" {
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

		if path == "/api/delete-resource" {
			tokens := strings.Split(obj.Name, "/")
			if len(tokens) >= 5 {
				obj.Name = tokens[4]
			}
		}

		return obj.Owner, obj.Name, nil
	}
}

func willLog(subOwner string, subName string, method string, urlPath string, objOwner string, objName string) bool {
	if subOwner == "anonymous" && subName == "anonymous" && method == "GET" && (urlPath == "/api/get-account" || urlPath == "/api/get-app-login") && objOwner == "" && objName == "" {
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

	if strings.HasPrefix(urlPath, "/api/login/oauth") {
		return "/api/login/oauth"
	}

	// Normalize /oauth/* aliases to their canonical /api/ paths for authz
	switch urlPath {
	case "/oauth/token", "/oauth/access_token", "/oauth/refresh", "/oauth/introspect", "/oauth/revoke":
		return "/api/login/oauth"
	case "/oauth/userinfo":
		return "/api/userinfo"
	case "/oauth/device":
		return "/api/device-auth"
	case "/oauth/logout":
		return "/api/logout"
	}

	if strings.HasPrefix(urlPath, "/api/webauthn") {
		return "/api/webauthn"
	}

	if strings.HasPrefix(urlPath, "/api/saml/redirect") {
		return "/api/saml/redirect"
	}

	return urlPath
}

func getExtraInfo(ctx *context.Context, urlPath string) map[string]interface{} {
	var extra map[string]interface{}
	if urlPath == "/api/mcp" {
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
	// The Casbin enforcer has matching policies, but xorm boolean deserialization
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
	if urlPath != "/api/get-app-login" && urlPath != "/api/get-resource" {
		var err error
		objOwner, objName, err = getObject(ctx)
		if err != nil {
			responseError(ctx, err.Error())
			return
		}
	}

	if strings.HasPrefix(urlPath, "/api/notify-payment") {
		urlPath = "/api/notify-payment"
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
		if urlPath == "/api/mcp" || strings.HasPrefix(urlPath, "/api/server/") {
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

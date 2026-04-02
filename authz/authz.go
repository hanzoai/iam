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

package authz

import (
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
	stringadapter "github.com/qiangmzsx/string-adapter/v2"
)

var Enforcer *casbin.Enforcer

func InitApi() {
	e, err := object.GetInitializedEnforcer(util.GetId("built-in", "api-enforcer-built-in"))
	if err != nil {
		panic(err)
	}

	Enforcer = e.Enforcer
	Enforcer.ClearPolicy()

	// if len(Enforcer.GetPolicy()) == 0 {
	if true {
		ruleText := `
p, built-in, *, *, *, *, *
p, app, *, *, *, *, *
p, *, !anonymous, POST, /api/add-organization, admin, *
p, *, !anonymous, POST, /api/update-organization, admin, *
p, *, !anonymous, POST, /api/delete-organization, admin, *
p, *, !anonymous, GET, /api/get-organizations, *, *
p, *, !anonymous, GET, /api/get-organization, *, *
p, *, !anonymous, POST, /api/add-application, *, *
p, *, !anonymous, POST, /api/update-application, *, *
p, *, !anonymous, POST, /api/delete-application, *, *
p, *, !anonymous, GET, /api/get-applications, *, *
p, *, *, POST, /api/signup, *, *
p, *, *, GET, /api/get-email-and-phone, *, *
p, *, *, POST, /api/login, *, *
p, *, *, GET, /api/get-app-login, *, *
p, *, *, POST, /api/logout, *, *
p, *, *, GET, /api/logout, *, *
p, *, *, POST, /api/sso-logout, *, *
p, *, *, GET, /api/sso-logout, *, *
p, *, *, POST, /api/callback, *, *
p, *, *, POST, /api/device-auth, *, *
p, *, *, GET, /api/get-account, *, *
p, *, *, GET, /api/userinfo, *, *
p, *, *, GET, /api/user, *, *
p, *, *, GET, /api/health, *, *
p, *, *, *, /api/webhook, *, *
p, *, *, GET, /api/get-qrcode, *, *
p, *, *, GET, /api/get-webhook-event, *, *
p, *, *, GET, /api/get-captcha-status, *, *
p, *, *, *, /api/login/oauth, *, *
p, *, *, POST, /api/oauth/register, *, *
p, *, *, GET, /api/get-application, *, *
p, *, *, GET, /api/get-organization-applications, *, *
p, *, *, GET, /api/get-user-application, *, *
p, *, *, POST, /api/upload-users, *, *
p, *, *, GET, /api/get-resources, *, *
p, *, *, GET, /api/get-records, *, *
p, *, *, POST, /api/unlink, *, *
p, *, *, POST, /api/set-password, *, *
p, *, *, POST, /api/send-verification-code, *, *
p, *, *, GET, /api/get-captcha, *, *
p, *, *, POST, /api/verify-captcha, *, *
p, *, *, POST, /api/verify-code, *, *
p, *, *, POST, /api/reset-email-or-phone, *, *
p, *, *, POST, /api/upload-resource, *, *
p, *, *, GET, /.well-known/openid-configuration, *, *
p, *, *, GET, /.well-known/webfinger, *, *
p, *, *, *, /.well-known/jwks, *, *
p, *, *, GET, /.well-known/acme-challenge, *, *
p, *, *, GET, /.well-known/:application/openid-configuration, *, *
p, *, *, GET, /.well-known/:application/webfinger, *, *
p, *, *, *, /.well-known/:application/jwks, *, *
p, *, *, GET, /api/get-saml-login, *, *
p, *, *, POST, /api/acs, *, *
p, *, *, GET, /api/saml/metadata, *, *
p, *, *, *, /api/saml/redirect, *, *
p, *, *, *, /cas, *, *
p, *, *, *, /scim, *, *
p, *, *, *, /api/webauthn, *, *
p, *, *, GET, /api/get-release, *, *
p, *, *, GET, /api/get-default-application, *, *
p, *, *, GET, /api/get-prometheus-info, *, *
p, *, *, *, /api/metrics, *, *
p, *, *, GET, /api/get-provider, *, *
p, *, *, GET, /api/get-organization-names, *, *
p, *, *, GET, /api/get-project, *, *
p, *, *, GET, /api/get-projects, *, *
p, *, *, GET, /api/get-organization-projects, *, *
p, *, *, GET, /api/get-all-objects, *, *
p, *, *, GET, /api/get-all-actions, *, *
p, *, *, GET, /api/get-all-roles, *, *
p, *, *, GET, /api/run-casbin-command, *, *
p, *, *, POST, /api/refresh-engines, *, *
p, *, *, GET, /api/get-invitation-info, *, *
p, *, *, GET, /api/faceid-signin-begin, *, *
p, *, *, GET, /api/registry/token, *, *
p, *, *, GET, /api/registry/jwks, *, *
p, *, *, POST, /api/sync-init-data, *, *
`

		sa := stringadapter.NewAdapter(ruleText)
		// load all rules from string adapter to enforcer's memory
		err = sa.LoadPolicy(Enforcer.GetModel())
		if err != nil {
			panic(err)
		}

		// save all rules from enforcer's memory to Xorm adapter (DB)
		// same as:
		// a.SavePolicy(Enforcer.GetModel())
		err = Enforcer.SavePolicy()
		if err != nil {
			panic(err)
		}
	}
}

func IsAllowed(subOwner string, subName string, method string, urlPath string, objOwner string, objName string, extraInfo map[string]interface{}) bool {
	if urlPath == "/api/mcp" {
		if detailPath, ok := extraInfo["detailPathUrl"].(string); ok {
			if detailPath == "initialize" || detailPath == "notifications/initialized" || detailPath == "ping" || detailPath == "tools/list" {
				return true
			}
		}
	}

	if conf.IsDemoMode() {
		if !isAllowedInDemoMode(subOwner, subName, method, urlPath, objOwner, objName) {
			return false
		}
	}

	user, err := object.GetUser(util.GetId(subOwner, subName))
	if err != nil {
		panic(err)
	}

	if subOwner == "app" {
		return true
	}

	if user != nil {
		if user.IsDeleted {
			return false
		}

		if user.IsGlobalAdmin() {
			return true
		}

		// Check IsAdmin from the loaded user struct. If xorm failed to read
		// the boolean correctly (known issue with Postgres), fall back to a
		// direct SQL query as a workaround.
		isAdmin := user.IsAdmin
		if !isAdmin {
			isAdmin = object.CheckUserIsAdminRaw(subOwner, subName)
		}

		if isAdmin && (subOwner == objOwner || objOwner == "admin") {
			return true
		}
	}

	res, err := Enforcer.Enforce(subOwner, subName, method, urlPath, objOwner, objName)
	if err != nil {
		panic(err)
	}

	if !res {
		res, err = object.CheckApiPermission(util.GetId(subOwner, subName), objOwner, urlPath, method)
		if err != nil {
			panic(err)
		}
	}

	return res
}

func isAllowedInDemoMode(subOwner string, subName string, method string, urlPath string, objOwner string, objName string) bool {
	if method == "POST" {
		if strings.HasPrefix(urlPath, "/api/login") || urlPath == "/api/logout" || urlPath == "/api/sso-logout" || urlPath == "/api/signup" || urlPath == "/api/callback" || urlPath == "/api/send-verification-code" || urlPath == "/api/send-email" || urlPath == "/api/verify-captcha" || urlPath == "/api/verify-code" || urlPath == "/api/check-user-password" || strings.HasPrefix(urlPath, "/api/mfa/") || urlPath == "/api/webhook" || urlPath == "/api/get-qrcode" || urlPath == "/api/refresh-engines" {
			return true
		} else if urlPath == "/api/update-user" {
			// Allow ordinary users to update their own information
			if (subOwner == objOwner && subName == objName || subOwner == "app") && !(subOwner == "built-in" && subName == "admin") {
				return true
			}
			return false
		} else if urlPath == "/api/upload-resource" {
			if subOwner == "app" && (subName == "hanzo-app" || subName == "app-console") {
				return true
			}
			return false
		} else {
			return false
		}
	}

	// If method equals GET
	return true
}

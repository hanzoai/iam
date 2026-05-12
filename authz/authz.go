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

	authzengine "github.com/casbin/casbin/v2"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
	stringadapter "github.com/qiangmzsx/string-adapter/v2"
)

var Enforcer *authzengine.Enforcer

func InitApi() {
	e, err := object.GetInitializedEnforcer(util.GetId("superuser", "api-enforcer-superuser"))
	if err != nil {
		panic(err)
	}

	Enforcer = e.Enforcer
	Enforcer.ClearPolicy()

	// if len(Enforcer.GetPolicy()) == 0 {
	if true {
		ruleText := `
p, superuser, *, *, *, *, *
p, app, *, *, *, *, *
p, *, !anonymous, POST, /v1/iam/add-organization, admin, *
p, *, !anonymous, POST, /v1/iam/update-organization, admin, *
p, *, !anonymous, POST, /v1/iam/delete-organization, admin, *
p, *, !anonymous, GET, /v1/iam/get-organizations, *, *
p, *, !anonymous, GET, /v1/iam/get-organization, *, *
p, *, !anonymous, POST, /v1/iam/add-application, *, *
p, *, !anonymous, POST, /v1/iam/update-application, *, *
p, *, !anonymous, POST, /v1/iam/delete-application, *, *
p, *, !anonymous, GET, /v1/iam/get-applications, *, *
p, *, *, POST, /v1/iam/signup, *, *
p, *, *, GET, /v1/iam/get-email-and-phone, *, *
p, *, *, POST, /v1/iam/login, *, *
p, *, *, GET, /v1/iam/get-app-login, *, *
p, *, *, POST, /v1/iam/logout, *, *
p, *, *, GET, /v1/iam/logout, *, *
p, *, *, POST, /v1/iam/sso-logout, *, *
p, *, *, GET, /v1/iam/sso-logout, *, *
p, *, *, POST, /v1/iam/callback, *, *
p, *, *, POST, /v1/iam/device-auth, *, *
p, *, *, GET, /v1/iam/get-account, *, *
p, *, *, GET, /v1/iam/userinfo, *, *
p, *, *, GET, /v1/iam/user, *, *
p, *, *, GET, /healthz, *, *
p, *, *, *, /v1/iam/webhook, *, *
p, *, *, GET, /v1/iam/get-qrcode, *, *
p, *, *, GET, /v1/iam/get-webhook-event, *, *
p, *, *, GET, /v1/iam/get-captcha-status, *, *
p, *, *, *, /login/oauth, *, *
p, *, *, POST, /oauth/register, *, *
p, *, *, GET, /v1/iam/get-application, *, *
p, *, *, GET, /v1/iam/get-organization-applications, *, *
p, *, *, GET, /v1/iam/get-user-application, *, *
p, *, *, POST, /v1/iam/upload-users, *, *
p, *, *, GET, /v1/iam/get-resources, *, *
p, *, *, GET, /v1/iam/get-records, *, *
p, *, *, POST, /v1/iam/unlink, *, *
p, *, *, POST, /v1/iam/set-password, *, *
p, *, *, POST, /v1/iam/send-verification-code, *, *
p, *, *, GET, /v1/iam/get-captcha, *, *
p, *, *, POST, /v1/iam/verify-captcha, *, *
p, *, *, POST, /v1/iam/verify-code, *, *
p, *, *, POST, /v1/iam/reset-email-or-phone, *, *
p, *, *, POST, /v1/iam/upload-resource, *, *
p, *, *, GET, /.well-known/openid-configuration, *, *
p, *, *, GET, /.well-known/webfinger, *, *
p, *, *, *, /.well-known/jwks, *, *
p, *, *, GET, /.well-known/acme-challenge, *, *
p, *, *, GET, /.well-known/:application/openid-configuration, *, *
p, *, *, GET, /.well-known/:application/webfinger, *, *
p, *, *, *, /.well-known/:application/jwks, *, *
p, *, *, GET, /v1/iam/get-saml-login, *, *
p, *, *, POST, /v1/iam/acs, *, *
p, *, *, GET, /v1/iam/saml/metadata, *, *
p, *, *, *, /v1/iam/saml/redirect, *, *
p, *, *, *, /cas, *, *
p, *, *, *, /scim, *, *
p, *, *, *, /v1/iam/webauthn, *, *
p, *, *, GET, /v1/iam/get-release, *, *
p, *, *, GET, /v1/iam/get-default-application, *, *
p, *, *, GET, /v1/iam/get-prometheus-info, *, *
p, *, *, *, /v1/iam/metrics, *, *
p, *, *, GET, /v1/iam/get-provider, *, *
p, *, *, GET, /v1/iam/get-organization-names, *, *
p, *, *, GET, /v1/iam/get-project, *, *
p, *, *, GET, /v1/iam/get-projects, *, *
p, *, *, GET, /v1/iam/get-organization-projects, *, *
p, *, *, GET, /v1/iam/get-all-objects, *, *
p, *, *, GET, /v1/iam/get-all-actions, *, *
p, *, *, GET, /v1/iam/get-all-roles, *, *
p, *, *, GET, /v1/iam/run-authz-command, *, *
p, *, *, GET, /v1/iam/get-invitation-info, *, *
p, *, *, GET, /v1/iam/faceid-signin-begin, *, *
p, *, *, GET, /v1/iam/registry/token, *, *
p, *, *, GET, /v1/iam/registry/jwks, *, *
p, *, *, POST, /v1/iam/sync-init-data, *, *
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
	if urlPath == "/v1/iam/mcp" {
		if detailPath, ok := extraInfo["detailPathUrl"].(string); ok {
			if detailPath == "initialize" || detailPath == "notifications/initialized" || detailPath == "ping" || detailPath == "tools/list" {
				return true
			}
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

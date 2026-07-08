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

package controllers

import (
	"context"
	"strings"
	"time"

	"github.com/hanzoai/beego/v2/core/logs"
	"github.com/hanzoai/beego/v2/server/web"
	"github.com/hanzoai/iam/mcpself"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// ApiController
// controller for handlers under /api uri
type ApiController struct {
	web.Controller
}

// RootController
// controller for handlers directly under / (root)
type RootController struct {
	ApiController
}

type SessionData struct {
	ExpireTime int64
}

// IsSuperAdmin reports whether the request's session principal is a Hanzo super
// admin (a member of conf.AdminOrg). This is the CANONICAL name for the gate.
func (c *ApiController) IsSuperAdmin() bool {
	isSuperAdmin, _ := c.isGlobalAdmin()

	return isSuperAdmin
}

// IsGlobalAdmin is the DEPRECATED alias of IsSuperAdmin, kept so existing call
// sites keep compiling during the SuperAdmin rename. New code MUST call
// IsSuperAdmin. It delegates — one derivation, one truth.
func (c *ApiController) IsGlobalAdmin() bool {
	return c.IsSuperAdmin()
}

// appMutationAllowed decides whether the caller may create / modify / delete
// the given application.
//
// V5/Red#6 (availability) + Red#7: app-mutation authz is org-unscoped (Casbin
// objOwner=*, any authenticated principal reaches the handler with no isAdmin
// check). The rule:
//   - global admin: unrestricted.
//   - app/M2M principal: already capability-gated (requireAppCapability
//     CapAppAdmin) upstream — trusted platform manager here.
//   - a capability-RESERVED app (the platform login/capability apps:
//     hanzo-console, hanzo-cloud, hanzo-chat, *-console, ...) may ONLY be
//     mutated by a global admin, REGARDLESS of its tenant Organization. This is
//     the Red#7 fix: admin/hanzo-console is Owner=admin, Organization=hanzo, so
//     an Organization-only scope let ANY hanzo-org principal (hanzo is the
//     default signup org) delete/rewrite the platform login app -> auth DoS /
//     OAuth-client takeover.
//   - otherwise: the caller must be an ADMIN of the app's OWN organization.
func (c *ApiController) appMutationAllowed(app *object.Application) bool {
	if c.IsGlobalAdmin() {
		return true
	}
	if object.IsAppUser(c.GetSessionUsername()) {
		return true
	}
	if app == nil {
		return false
	}
	if object.AppNameIsCapabilityReserved(app.Name) {
		return false
	}
	cu := c.getCurrentUser()
	return cu != nil && cu.IsAdmin && app.Organization != "" && app.Organization == cu.Owner
}

func (c *ApiController) IsAdmin() bool {
	isGlobalAdmin, user := c.isGlobalAdmin()
	if !isGlobalAdmin && user == nil {
		return false
	}

	return isGlobalAdmin || user.IsAdmin
}

func (c *ApiController) IsAdminOrSelf(user2 *object.User) bool {
	isGlobalAdmin, user := c.isGlobalAdmin()
	if isGlobalAdmin || (user != nil && user.IsAdmin) {
		return true
	}

	if user == nil || user2 == nil {
		return false
	}

	if user.Owner == user2.Owner && user.Name == user2.Name {
		return true
	}
	return false
}

func (c *ApiController) isGlobalAdmin() (bool, *object.User) {
	username := c.GetSessionUsername()
	if object.IsAppUser(username) {
		// SECURITY (Red R-1): an app/<name> (M2M client_credentials) principal is
		// NOT a global admin. It has no User row; its authority is granted per
		// capability (object.AppAllowedForCapability) for mutations and via
		// explicit cross-org read permission (object.CheckUserPermission) for
		// reads. Returning false makes the H-4 privileged-field wall
		// (CheckPermissionForUpdateUser) deny owner/is_admin mutation by an app
		// and the get-application/get-user responses fall to the masked,
		// non-admin view for app callers.
		return false, nil
	}

	user := c.getCurrentUser()
	if user == nil {
		return false, nil
	}

	return user.IsGlobalAdmin(), user
}

func (c *ApiController) getCurrentUser() *object.User {
	var user *object.User
	var err error
	userId := c.GetSessionUsername()
	if userId == "" {
		user = nil
	} else {
		user, err = object.GetUser(userId)
		if err != nil {
			c.ResponseError(err.Error())
			return nil
		}
	}
	return user
}

// GetSessionUsername ...
func (c *ApiController) GetSessionUsername() string {
	// prefer username stored in Beego context by ApiFilter
	if ctxUser := c.Ctx.Input.GetData("currentUserId"); ctxUser != nil {
		if username, ok := ctxUser.(string); ok {
			return username
		}
	}

	// check if user session expired
	sessionData := c.GetSessionData()

	if sessionData != nil &&
		sessionData.ExpireTime != 0 &&
		sessionData.ExpireTime < time.Now().Unix() {
		c.ClearUserSession()
		return ""
	}

	user := c.GetSession("username")
	if user == nil {
		return ""
	}

	return user.(string)
}

// GetPaidUsername ...
func (c *ApiController) GetPaidUsername() string {
	// check if user session expired
	sessionData := c.GetSessionData()

	if sessionData != nil &&
		sessionData.ExpireTime != 0 &&
		sessionData.ExpireTime < time.Now().Unix() {
		c.ClearUserSession()
		return ""
	}

	user := c.GetSession("paidUsername")
	if user == nil {
		return ""
	}

	return user.(string)
}

func (c *ApiController) GetSessionToken() string {
	accessToken := c.GetSession("accessToken")
	if accessToken == nil {
		return ""
	}

	return accessToken.(string)
}

func (c *ApiController) IsServiceTokenAuthenticated() bool {
	ctxValue := c.Ctx.Input.GetData("serviceTokenAuthenticated")
	enabled, ok := ctxValue.(bool)
	return ok && enabled
}

func (c *ApiController) GetSessionApplication() *object.Application {
	clientId := c.GetSession("aud")
	if clientId == nil {
		return nil
	}
	application, err := object.GetApplicationByClientId(clientId.(string))
	if err != nil {
		c.ResponseError(err.Error())
		return nil
	}

	return application
}

func (c *ApiController) ClearUserSession() {
	c.SetSessionUsername("")
	c.SetSessionData(nil)
	_ = c.SessionRegenerateID()
}

func (c *ApiController) ClearTokenSession() {
	c.SetSessionToken("")
}

func (c *ApiController) GetSessionOidc() (string, string) {
	sessionData := c.GetSessionData()
	if sessionData != nil &&
		sessionData.ExpireTime != 0 &&
		sessionData.ExpireTime < time.Now().Unix() {
		c.ClearUserSession()
		return "", ""
	}
	scopeValue := c.GetSession("scope")
	audValue := c.GetSession("aud")
	var scope, aud string
	var ok bool
	if scope, ok = scopeValue.(string); !ok {
		scope = ""
	}
	if aud, ok = audValue.(string); !ok {
		aud = ""
	}
	return scope, aud
}

// SetSessionUsername ...
// SetSessionUsername records the authenticated user on the session. On the
// authentication transition (a non-empty user) it FIRST regenerates the session
// id — issuing a fresh sid and destroying the one the browser presented — so a
// session id planted before login (session fixation) can never survive the
// sign-in and be replayed by an attacker. This is the single chokepoint every
// sign-in path funnels through (password, SSO/social, OTP verification, WebAuthn,
// web3), so the defense cannot be bypassed per-path — the same reason the
// approval stamp had to live on the common AddUser path, not each caller.
//
// SessionRegenerateID migrates existing session data to the new sid and deletes
// the old sid (provider.SessionRegenerate), so pre-auth state is preserved while
// the pre-auth id is invalidated. De-authentication (empty user) already
// regenerates in ClearUserSession, so we skip the redundant regen here.
func (c *ApiController) SetSessionUsername(user string) {
	if user != "" {
		_ = c.SessionRegenerateID()
	}
	c.SetSession("username", user)
}

func (c *ApiController) SetSessionToken(accessToken string) {
	c.SetSession("accessToken", accessToken)
}

// GetSessionData ...
func (c *ApiController) GetSessionData() *SessionData {
	session := c.GetSession("SessionData")
	if session == nil {
		return nil
	}

	sessionData := &SessionData{}
	err := util.JsonToStruct(session.(string), sessionData)
	if err != nil {
		logs.Error("GetSessionData failed, error: %s", err)
		return nil
	}

	return sessionData
}

// SetSessionData ...
func (c *ApiController) SetSessionData(s *SessionData) {
	if s == nil {
		c.DelSession("SessionData")
		return
	}

	c.SetSession("SessionData", util.StructToJson(s))
}

func (c *ApiController) setMfaUserSession(userId string) {
	c.SetSession(object.MfaSessionUserId, userId)
}

func (c *ApiController) getMfaUserSession() string {
	userId := c.Ctx.Input.CruSession.Get(context.Background(), object.MfaSessionUserId)
	if userId == nil {
		return ""
	}
	return userId.(string)
}

func (c *ApiController) setExpireForSession(cookieExpireInHours int64) {
	timestamp := time.Now().Unix()
	if cookieExpireInHours == 0 {
		cookieExpireInHours = 720
	}
	timestamp += 3600 * cookieExpireInHours
	c.SetSessionData(&SessionData{
		ExpireTime: timestamp,
	})
}

func wrapActionResponse(affected bool, e ...error) *Response {
	if len(e) != 0 && e[0] != nil {
		return &Response{Status: "error", Msg: e[0].Error()}
	} else if affected {
		return &Response{Status: "ok", Msg: "", Data: "Affected"}
	} else {
		return &Response{Status: "ok", Msg: "", Data: "Unaffected"}
	}
}

func wrapErrorResponse(err error) *Response {
	if err == nil {
		return &Response{Status: "ok", Msg: ""}
	} else {
		return &Response{Status: "error", Msg: err.Error()}
	}
}

func (c *ApiController) Finish() {
	// API-latency metric is scoped to the canonical /v1/iam/* surface —
	// the only shape IAM serves. There is no /api prefix (HIP-0111).
	if strings.HasPrefix(c.Ctx.Input.URL(), "/v1/iam") {
		startTime := c.Ctx.Input.GetData("startTime")
		if startTime != nil {
			latency := time.Since(startTime.(time.Time)).Milliseconds()
			object.ApiLatency.WithLabelValues(c.Ctx.Input.URL(), c.Ctx.Input.Method()).Observe(float64(latency))
		}
	}
	c.Controller.Finish()
}

func (c *ApiController) McpResponseError(id interface{}, code int, message string, data interface{}) {
	resp := mcpself.BuildMcpResponse(id, nil, &mcpself.McpError{
		Code:    code,
		Message: message,
		Data:    data,
	})
	c.Ctx.Output.Header("Content-Type", "application/json")
	c.Data["json"] = resp
	c.ServeJSON()
}

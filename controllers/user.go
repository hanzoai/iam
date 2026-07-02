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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hanzoai/beego/v2/core/utils/pagination"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// GetGlobalUsers
// @Title GetGlobalUsers
// @Tag User API
// @Description get global users
// @Success 200 {array} object.User The Response object
// @router /get-global-users [get]
func (c *ApiController) GetGlobalUsers() {
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		users, err := object.GetMaskedUsers(object.GetGlobalUsers())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(users)
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetGlobalUserCount(field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
		users, err := object.GetPaginationGlobalUsers(paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		users, err = object.GetMaskedUsers(users)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(users, paginator.Nums())
	}
}

// GetUsers
// @Title GetUsers
// @Tag User API
// @Description
// @Param   owner     query    string  true        "The owner of users"
// @Success 200 {array} object.User The Response object
// @router /get-users [get]
func (c *ApiController) GetUsers() {
	// V5/N4 (cross-tenant disclosure, defense in depth): the user LIST is the
	// crown-jewel roster (name/email/passwordSalt). The authz layer still waves
	// through an app/M2M principal (subOwner=="app"), so a tenant admin who
	// reads its own org's app clientSecret could mint an app token and
	// enumerate owner=admin (the 9 superusers) here — reproducing the V5 leak.
	// Gate the enumeration on the SAME user-admin capability the mutations use:
	// a human keeps normal authz (owner=admin already denied for non-global by
	// authz.IsAllowed); a platform app in IAM_USER_ADMIN_APPS (hanzo-cloud /
	// *-console — the superadmin console backend) passes; a tenant app is
	// denied. (Point lookups by accessKey/userId use get-user, not this.)
	if !c.requireAppCapability(object.CapUserAdmin) {
		return
	}

	owner := c.Ctx.Input.Query("owner")
	groupName := c.Ctx.Input.Query("groupName")
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		if groupName != "" {
			users, err := object.GetMaskedUsers(object.GetGroupUsers(util.GetId(owner, groupName)))
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			c.ResponseOk(users)
			return
		}

		users, err := object.GetMaskedUsers(object.GetUsers(owner))
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(users)
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetUserCount(owner, field, value, groupName)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
		users, err := object.GetPaginationUsers(owner, paginator.Offset(), limit, field, value, sortField, sortOrder, groupName)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		users, err = object.GetMaskedUsers(users)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(users, paginator.Nums())
	}
}

// GetUser
// @Title GetUser
// @Tag User API
// @Description get user
// @Param   id     query    string  false        "The id ( owner/name ) of the user"
// @Param   owner  query    string  false        "The owner of the user"
// @Param   email  query    string  false 	     "The email of the user"
// @Param   phone  query    string  false 	     "The phone of the user"
// @Param   userId query    string  false 	     "The userId of the user"
// @Success 200 {object} object.User The Response object
// @router /get-user [get]
func (c *ApiController) GetUser() {
	id := c.Ctx.Input.Query("id")
	email := c.Ctx.Input.Query("email")
	phone := c.Ctx.Input.Query("phone")
	userId := c.Ctx.Input.Query("userId")
	accessKey := c.Ctx.Input.Query("accessKey")
	owner := c.Ctx.Input.Query("owner")
	var err error
	var userFromUserId *object.User
	if userId != "" && owner != "" {
		userFromUserId, err = object.GetUserByUserId(owner, userId)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if userFromUserId == nil {
			c.ResponseOk(nil)
			return
		}

		id = util.GetId(userFromUserId.Owner, userFromUserId.Name)
	}

	var user *object.User
	if id == "" && owner == "" {
		// When no id/owner is provided, require authentication and scope
		// the lookup to the caller's organization to prevent cross-tenant
		// user enumeration.
		requestUserId := c.GetSessionUsername()
		if requestUserId == "" {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return
		}
		callerOwner := util.GetOwnerFromId(requestUserId)

		switch {
		case accessKey != "":
			user, err = object.GetUserByAccessKey(accessKey)
		case email != "":
			user, err = object.GetUserByEmail(callerOwner, email)
		case phone != "":
			user, err = object.GetUserByPhone(callerOwner, phone)
		case userId != "":
			user, err = object.GetUserByUserId(callerOwner, userId)
		}
	} else {
		if owner == "" {
			owner = util.GetOwnerFromId(id)
		}

		// V5/N4/Red#3 (cross-tenant disclosure): the authz-layer subOwner=="app"
		// blanket lets an app/M2M principal past wire authz, so a tenant app
		// (whose own clientSecret its admin can read) could otherwise read ANY
		// user by id/owner/email/phone — email, passwordSalt, and the hk-
		// accessKey — across the tenant boundary. Gate app single-reads on a
		// user-read capability: the global-admin org (guessable admin/z etc.)
		// needs CapUserAdmin; any other org needs CapUserAdmin OR CapKeyMint
		// (hanzo-chat resolves each user's hk- key by org+email). The
		// accessKey-lookup branch is exempt — it already requires possessing the
		// secret value (the LLM billing gate). Humans keep normal authz (bearer
		// non-global is already denied owner=admin by authz.IsAllowed).
		if accessKey == "" && object.IsAppUser(c.GetSessionUsername()) {
			caller := c.GetSessionUsername()
			allowed := object.AppAllowedForCapability(caller, object.CapUserAdmin)
			if !allowed && owner != conf.AdminOrg {
				allowed = object.AppAllowedForCapability(caller, object.CapKeyMint)
			}
			if !allowed {
				c.ResponseError(c.T("auth:Unauthorized operation"))
				return
			}
		}

		switch {
		case accessKey != "":
			user, err = object.GetUserByAccessKey(accessKey)
		case email != "":
			user, err = object.GetUserByEmail(owner, email)
		case phone != "":
			user, err = object.GetUserByPhone(owner, phone)
		case userId != "":
			user = userFromUserId
		default:
			user, err = object.GetUser(id)
		}
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	var organization *object.Organization
	if user != nil {
		organization, err = object.GetOrganizationByUser(user)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if organization == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The organization: %s does not exist"), owner))
			return
		}

		if !organization.IsProfilePublic && !c.IsServiceTokenAuthenticated() {
			requestUserId := c.GetSessionUsername()
			var hasPermission bool
			hasPermission, err = object.CheckUserPermission(requestUserId, user.GetId(), false, c.GetAcceptLanguage())
			if !hasPermission {
				c.ResponseError(err.Error())
				return
			}
		}
	}

	if user != nil {
		user.MultiFactorAuths = object.GetAllMfaProps(user, true)
	}

	err = object.ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	isAdminOrSelf := c.IsAdminOrSelf(user)
	// V5/Red#3: GetMaskedUser masks accessKey/accessSecret (the hk- credential)
	// for every non-admin/non-self caller. A credential-capable PLATFORM app
	// still needs the user's key (hanzo-chat CapKeyMint meters LLM calls per
	// user; cloud/console CapUserAdmin) — re-reveal ONLY these two fields for
	// such apps, never OriginalToken/OAuth.
	revealCredToApp := !isAdminOrSelf && user != nil && object.IsAppUser(c.GetSessionUsername()) &&
		(object.AppAllowedForCapability(c.GetSessionUsername(), object.CapKeyMint) ||
			object.AppAllowedForCapability(c.GetSessionUsername(), object.CapUserAdmin))
	var keptAccessKey, keptAccessSecret string
	if revealCredToApp {
		keptAccessKey, keptAccessSecret = user.AccessKey, user.AccessSecret
	}
	user, err = object.GetMaskedUser(user, isAdminOrSelf)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if revealCredToApp && user != nil {
		user.AccessKey, user.AccessSecret = keptAccessKey, keptAccessSecret
	}

	if organization != nil && user != nil {
		user, err = object.GetFilteredUser(user, c.IsAdmin(), c.IsAdminOrSelf(user), organization.AccountItems)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	c.ResponseOk(user)
}

// UpdateUser
// @Title UpdateUser
// @Tag User API
// @Description update user
// @Param   id     query    string  false        "The id ( owner/name ) of the user"
// @Param   userId query    string  false        "The userId (UUID) of the user"
// @Param   owner  query    string  false        "The owner of the user (required when using userId)"
// @Param   body    body   object.User  true        "The details of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /update-user [post]
func (c *ApiController) UpdateUser() {
	// An app/<name> credential may mutate another user's record (password,
	// is_admin, owner, email, phone, type, balance, access_key, ...) ONLY if
	// allowlisted for the user-admin capability (fail-secure). Humans keep the
	// existing self / org-admin / global-admin authorization below.
	if !c.requireAppCapability(object.CapUserAdmin) {
		return
	}

	id := c.Ctx.Input.Query("id")
	userId := c.Ctx.Input.Query("userId")
	owner := c.Ctx.Input.Query("owner")
	columnsStr := c.Ctx.Input.Query("columns")

	var user object.User
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Defense-in-depth for the by-attribute discriminator: the synthetic
	// "application" Type is reserved for users minted by
	// GetClientCredentialsToken (object/token_oauth.go:1044-1049). A
	// tenant admin must not be able to persist Type="application" on a
	// real human user — doing so would (a) bypass the by-attribute
	// endpoint's Type-based discriminator and (b) generally let a normal
	// user impersonate a service principal. The only legitimate writer
	// of Type="application" is the bootstrap path inside the built-in
	// org (where IAM itself seeds its own admin app's user). The full
	// defense lives in users_by_attribute.go (4-field check); this is
	// the second wall.
	if !rejectApplicationTypePromotion(c, &user) {
		return
	}

	if id == "" && userId == "" {
		id = c.GetSessionUsername()
		if id == "" {
			c.ResponseError(c.T("general:Missing parameter"))
			return
		}
	}

	var userFromUserId *object.User
	if userId != "" && owner != "" {
		userFromUserId, err = object.GetUserByUserId(owner, userId)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if userFromUserId == nil {
			c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), userId))
			return
		}

		id = util.GetId(userFromUserId.Owner, userFromUserId.Name)
	}

	var oldUser *object.User
	if userId != "" {
		oldUser = userFromUserId
	} else {
		oldUser, err = object.GetUser(id)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	if oldUser == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), id))
		return
	}

	if oldUser.Owner == "admin" && oldUser.Name == "admin" && (user.Owner != "admin" || user.Name != "admin") {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	if user.MfaEmailEnabled && user.Email == "" {
		c.ResponseError(c.T("user:MFA email is enabled but email is empty"))
		return
	}

	if user.MfaPhoneEnabled && user.Phone == "" {
		c.ResponseError(c.T("user:MFA phone is enabled but phone number is empty"))
		return
	}

	if msg := object.CheckUpdateUser(oldUser, &user, c.GetAcceptLanguage()); msg != "" {
		c.ResponseError(msg)
		return
	}

	isUsernameLowered := conf.GetConfigBool("isUsernameLowered")
	if isUsernameLowered {
		user.Name = strings.ToLower(user.Name)
	}

	isAdmin := c.IsAdmin()
	isGlobalAdmin := c.IsGlobalAdmin()
	allowDisplayNameEmpty := c.Ctx.Input.Query("allowEmpty") != ""
	if pass, err := object.CheckPermissionForUpdateUser(oldUser, &user, isAdmin, isGlobalAdmin, allowDisplayNameEmpty, c.GetAcceptLanguage()); !pass {
		c.ResponseError(err)
		return
	}

	columns := []string{}
	if columnsStr != "" {
		columns = strings.Split(columnsStr, ",")
	}

	affected, err := object.UpdateUser(id, &user, columns, isAdmin)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if affected {
		err = object.UpdateUserToOriginalDatabase(&user)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	c.Data["json"] = wrapActionResponse(affected)
	c.ServeJSON()
}

// MintUserKeys
// @Title MintUserKeys
// @Tag User API
// @Description (re)generate the per-user hk- Cloud API key (User.AccessKey /
//
//	User.AccessSecret) for the target user and return the new accessKey. This is
//	the self-serve minting primitive: an allowlisted confidential client (e.g.
//	the console, authenticated by clientId+clientSecret) calls it on behalf of
//	its authenticated end-user — authorization is enforced in
//	resolveTargetUserForKeys (admin OR self OR IAM_KEY_MINT_ALLOWED_APPS). It is
//	deliberately NOT routed under the add-/update- prefixes so the name-character
//	FieldValidationFilter does not reject email-named users, and the object-layer
//	mint (object.AddUserKeys) writes ONLY the two access-key columns, never
//	re-validating the (possibly email-named) `name`.
//
// @Param   id    query   string  true  "The user ID (<org>/<name>)"
// @Success 200 {object} controllers.Response The Response object
// @router /mint-user-keys [post]
func (c *ApiController) MintUserKeys() {
	user, ok := c.resolveTargetUserForKeys()
	if !ok {
		return
	}

	if _, err := object.AddUserKeys(user, c.IsAdmin()); err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Return ONLY the public-facing accessKey (the hk- key the caller presents in
	// `Authorization: Bearer hk-…`). The accessSecret stays server-side.
	c.ResponseOk(map[string]string{
		"owner":     user.Owner,
		"name":      user.Name,
		"accessKey": user.AccessKey,
	})
}

// IssueUserToken
// @Title IssueUserToken
// @Tag User API
// @Description Issue a short-lived, user-bound IAM JWT for a target user, to a
//
//	confidential trusted client (e.g. hanzo-console) that forwards it to a
//	resource server (e.g. commerce) which derives the user's org from the
//	verified `owner` claim. This is the SSR analogue of a browser presenting
//	its own IAM token: a server-side app that holds only an identity REFERENCE
//	(the session sub) — not a forwardable token — gets a per-user token to act
//	on the user's behalf, so the resource server enforces tenant isolation
//	server-side instead of trusting a shared, all-org service token.
//
// Authorization is IDENTICAL to MintUserKeys (resolveTargetUserForKeys): a
// global admin, the target user themselves, or an app in
// IAM_KEY_MINT_ALLOWED_APPS (CapKeyMint). Both primitives produce a credential
// that bills the user's org, so they share ONE trust boundary — issuing a token
// is no more privileged than minting that user's hk- key, which the same
// callers already do.
//
// @Param   id    query   string  true   "The user ID (<org>/<name>)"
// @Param   aud   query   string  false  "Explicit token audience (RFC 8707). Set to a value the resource server accepts; defaults to the minting app's clientId."
// @Param   scope query   string  false  "OAuth scope (default: profile)"
// @Success 200 {object} controllers.Response The Response object
// @router /issue-user-token [post]
func (c *ApiController) IssueUserToken() {
	user, ok := c.resolveTargetUserForKeys()
	if !ok {
		return
	}

	audience := c.Ctx.Input.Query("aud")
	scope := c.Ctx.Input.Query("scope")
	if scope == "" {
		scope = "profile"
	}

	application, err := object.GetApplicationByUser(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError(fmt.Sprintf("the application for user %s is not found", user.Id))
		return
	}

	token, err := object.GetUserTokenForAudience(application, user, audience, scope, c.getEffectiveHost())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Return ONLY the access token + its lifetime. No refresh token: this is a
	// short-lived, forward-and-discard credential — the caller re-issues from
	// the user's session when it expires (fail-closed), never persists it.
	c.ResponseOk(map[string]interface{}{
		"owner":       user.Owner,
		"name":        user.Name,
		"accessToken": token.AccessToken,
		"expiresIn":   token.ExpiresIn,
		"tokenType":   "Bearer",
	})
}

// RevokeUserKeys
// @Title RevokeUserKeys
// @Tag User API
// @Description clear the per-user hk- Cloud API key for the target user.
// @Param   id    query   string  true  "The user ID (<org>/<name>)"
// @Success 200 {object} controllers.Response The Response object
// @router /revoke-user-keys [post]
func (c *ApiController) RevokeUserKeys() {
	user, ok := c.resolveTargetUserForKeys()
	if !ok {
		return
	}

	if _, err := object.RevokeUserKeys(user, c.IsAdmin()); err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(map[string]string{"owner": user.Owner, "name": user.Name})
}

// resolveTargetUserForKeys loads the user the key operation targets AND enforces
// the caller→target authorization binding (the security boundary for the hk-
// minting primitive). Without this, the blanket `p, app, *, *, *, *, *` Casbin
// grant would let ANY confidential client mint a working billing key for ANY
// user in ANY org. Authorization, in order:
//
//   - global admin: may act on any user.
//   - the target user themselves (session/Bearer sub == target id): may act on
//     their own key.
//   - an allowlisted app (IAM_KEY_MINT_ALLOWED_APPS, e.g. hanzo-console): may act
//     on any user — it is a trusted tenant-isolation layer that has already
//     verified the end-user owns the target id.
//
// Any other caller (a non-allowlisted app, an anonymous request) → 403.
// Returns (nil,false) — having written the error response — on any failure.
func (c *ApiController) resolveTargetUserForKeys() (*object.User, bool) {
	caller := c.GetSessionUsername()
	if caller == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return nil, false
	}

	id := c.Ctx.Input.Query("id")
	if id == "" {
		// No explicit target → operate on the caller's own identity (only valid
		// for a real end-user caller, not an app principal).
		id = caller
	}
	if id == "" || object.IsAppUser(id) {
		c.ResponseError(c.T("general:Missing parameter"), "Missing parameter")
		return nil, false
	}

	// Authorization binding. NOTE: c.IsAdmin() / isGlobalAdmin() treat EVERY app
	// principal as a global admin (controllers/base.go: `if IsAppUser(username)
	// { return true }`) — so it CANNOT be used to gate apps here, or every
	// confidential client would pass. We branch on the caller kind explicitly:
	//
	//   - app caller  → must be in IAM_KEY_MINT_ALLOWED_APPS (fail-secure). A
	//     non-allowlisted app (kms, gateway, any SDK client) is rejected, which
	//     closes the cross-tenant key-harvest the blanket Casbin `p, app, *…`
	//     grant otherwise allows.
	//   - human caller → allowed only on their OWN identity (caller == id),
	//     UNLESS they are a real global-admin USER.
	if object.IsAppUser(caller) {
		// Folded into the one app-capability helper (object.AppAllowedForCapability)
		// so key-mint shares the same fail-secure IAM_KEY_MINT_ALLOWED_APPS
		// allowlist mechanism as password/user/app mutations.
		if !object.AppAllowedForCapability(caller, object.CapKeyMint) {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return nil, false
		}
	} else {
		realAdmin := false
		if u, err := object.GetUser(caller); err == nil && u != nil {
			realAdmin = u.IsGlobalAdmin() || u.IsAdmin
		}
		if caller != id && !realAdmin {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return nil, false
		}
	}

	user, err := object.GetUser(id)
	if err != nil {
		c.ResponseError(err.Error())
		return nil, false
	}
	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), id))
		return nil, false
	}
	return user, true
}

// AddUser
// @Title AddUser
// @Tag User API
// @Description add user
// @Param   body    body   object.User  true        "The details of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /add-user [post]
func (c *ApiController) AddUser() {
	// An app/<name> credential may create users (incl. privileged ones, e.g.
	// owner=admin == global admin) ONLY if allowlisted for the user-admin
	// capability (fail-secure). Humans keep their existing authorization
	// (Casbin + per-field checks); self-service registration uses /signup.
	if !c.requireAppCapability(object.CapUserAdmin) {
		return
	}

	var user object.User
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Defense-in-depth: see UpdateUser. Type="application" is the
	// client_credentials discriminator and must not be settable by a
	// tenant-admin-created user.
	if !rejectApplicationTypePromotion(c, &user) {
		return
	}

	if err := checkQuotaForUser(); err != nil {
		c.ResponseError(err.Error())
		return
	}

	emptyUser := object.User{}
	msg := object.CheckUpdateUser(&emptyUser, &user, c.GetAcceptLanguage())
	if msg != "" {
		c.ResponseError(msg)
		return
	}

	// Set RegisterSource based on the current user if not already set
	if user.RegisterType == "" {
		user.RegisterType = "Add User"
	}
	if user.RegisterSource == "" {
		currentUser := c.getCurrentUser()
		if currentUser != nil {
			user.RegisterSource = currentUser.GetId()
		}
	}

	c.Data["json"] = wrapActionResponse(object.AddUser(&user, c.GetAcceptLanguage()))
	c.ServeJSON()
}

// DeleteUser
// @Title DeleteUser
// @Tag User API
// @Description delete user
// @Param   body    body   object.User  true        "The details of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-user [post]
func (c *ApiController) DeleteUser() {
	// An app/<name> credential may delete users ONLY if allowlisted for the
	// user-admin capability (fail-secure). Humans keep their existing
	// authorization (Casbin). This handler had no controller-level admin
	// check, so the blanket app privilege was the only gate.
	if !c.requireAppCapability(object.CapUserAdmin) {
		return
	}

	var user object.User
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user.Owner == conf.AdminOrg && user.Name == conf.AdminUser {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteUser(&user))
	c.ServeJSON()
}

// GetEmailAndPhone
// @Title GetEmailAndPhone
// @Tag User API
// @Description get email and phone by username
// @Param   username    formData   string  true        "The username of the user"
// @Param   organization    formData   string  true        "The organization of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /get-email-and-phone [get]
func (c *ApiController) GetEmailAndPhone() {
	organization := c.Ctx.Request.Form.Get("organization")
	username := c.Ctx.Request.Form.Get("username")

	enableErrorMask2 := conf.GetConfigBool("enableErrorMask2")
	if enableErrorMask2 {
		c.ResponseError("Error")
		return
	}

	user, err := object.GetUserByFields(organization, username)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), util.GetId(organization, username)))
		return
	}

	respUser := object.User{Name: user.Name}
	var contentType string
	switch username {
	case user.Email:
		contentType = "email"
		respUser.Email = user.Email
	case user.Phone:
		contentType = "phone"
		respUser.Phone = user.Phone
	case user.Name:
		contentType = "username"
		respUser.Email = util.GetMaskedEmail(user.Email)
		respUser.Phone = util.GetMaskedPhone(user.Phone)
	}

	c.ResponseOk(respUser, contentType)
}

// SetPassword
// @Title SetPassword
// @Tag Account API
// @Description set password
// @Param   userOwner   formData    string  true        "The owner of the user"
// @Param   userName   formData    string  true        "The name of the user"
// @Param   oldPassword   formData    string  true        "The old password of the user"
// @Param   newPassword   formData    string  true        "The new password of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /set-password [post]
func (c *ApiController) SetPassword() {
	// A confidential-client (app/<name>) principal is NOT a blanket global
	// admin: resetting another user's password requires the password-admin
	// capability allowlist (fail-secure). Humans are unaffected and remain
	// gated below by CheckUserPermission (self / org-admin / global-admin) or
	// the verification-code self-service path.
	if !c.requireAppCapability(object.CapUserPasswordAdmin) {
		return
	}

	userOwner := c.Ctx.Request.Form.Get("userOwner")
	userName := c.Ctx.Request.Form.Get("userName")
	oldPassword := c.Ctx.Request.Form.Get("oldPassword")
	newPassword := c.Ctx.Request.Form.Get("newPassword")
	code := c.Ctx.Request.Form.Get("code")

	// if userOwner == "hanzo" && userName == "admin" {
	//	c.ResponseError(c.T("auth:Unauthorized operation"))
	//	return
	// }

	userId := util.GetId(userOwner, userName)

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), userId))
		return
	}

	// Get organization to check for password obfuscation settings
	organization, err := object.GetOrganizationByUser(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if organization == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:the organization: %s is not found"), user.Owner))
		return
	}

	// Deobfuscate passwords if organization has password obfuscator configured
	// Note: Deobfuscation is optional - if it fails, we treat the password as plain text
	// This allows SDKs and raw HTTP API calls to work without obfuscation support
	if organization.PasswordObfuscatorType != "" && organization.PasswordObfuscatorType != "Plain" {
		if oldPassword != "" {
			deobfuscatedOldPassword, deobfuscateErr := util.GetUnobfuscatedPassword(organization.PasswordObfuscatorType, organization.PasswordObfuscatorKey, oldPassword)
			if deobfuscateErr == nil {
				oldPassword = deobfuscatedOldPassword
			}
		}

		if newPassword != "" {
			deobfuscatedNewPassword, deobfuscateErr := util.GetUnobfuscatedPassword(organization.PasswordObfuscatorType, organization.PasswordObfuscatorKey, newPassword)
			if deobfuscateErr == nil {
				newPassword = deobfuscatedNewPassword
			}
		}
	}

	if strings.Contains(newPassword, " ") {
		c.ResponseError(c.T("user:New password cannot contain blank space."))
		return
	}

	requestUserId := c.GetSessionUsername()
	if requestUserId == "" && code == "" {
		c.ResponseError(c.T("general:Please login first"), "Please login first")
		return
	} else if code == "" {
		hasPermission, err := object.CheckUserPermission(requestUserId, userId, true, c.GetAcceptLanguage())
		if !hasPermission {
			c.ResponseError(err.Error())
			return
		}
	} else {
		if code != c.GetSession("verifiedCode") {
			c.ResponseError(c.T("general:Missing parameter"))
			return
		}
		if userId != c.GetSession("verifiedUserId") {
			c.ResponseError(c.T("general:Wrong userId"))
			return
		}
		c.SetSession("verifiedCode", "")
		c.SetSession("verifiedUserId", "")
	}

	targetUser, err := object.GetUser(userId)
	if targetUser == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), userId))
		return
	}
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	isAdmin := c.IsAdmin()
	if isAdmin {
		if oldPassword != "" {
			err = object.CheckPassword(targetUser, oldPassword, c.GetAcceptLanguage())
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		}
	} else if code == "" {
		if targetUser.Password != "" || user.Ldap != "" {
			if user.Ldap == "" {
				err = object.CheckPassword(targetUser, oldPassword, c.GetAcceptLanguage())
			} else {
				err = object.CheckLdapUserPassword(targetUser, oldPassword, c.GetAcceptLanguage())
			}
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		}
	}

	msg := object.CheckPasswordComplexity(targetUser, newPassword, c.GetAcceptLanguage())
	if msg != "" {
		c.ResponseError(msg)
		return
	}

	// Check if the new password is the same as the current password
	if !object.CheckPasswordNotSameAsCurrent(targetUser, newPassword, organization) {
		c.ResponseError(c.T("user:The new password must be different from your current password"))
		return
	}

	application, err := object.GetApplicationByUser(targetUser)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:the application for user %s is not found"), userId))
		return
	}

	clientIp := util.GetClientIpFromRequest(c.Ctx.Request)
	err = object.CheckEntryIp(clientIp, targetUser, application, organization, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Set the plaintext only. object.UpdateUser is the single place that
	// hashes a changed password (via UpdateUserPassword). Pre-hashing here
	// made UpdateUser hash the already-hashed value a SECOND time —
	// argon2id(argon2id(pw)) / bcrypt(bcrypt(pw)) — which no login can ever
	// verify, silently locking every password reset out. One password,
	// hashed exactly once, in one place.
	targetUser.Password = newPassword
	targetUser.NeedUpdatePassword = false
	targetUser.LastChangePasswordTime = util.GetCurrentTime()

	if user.Ldap == "" {
		_, err = object.UpdateUser(userId, targetUser, []string{"password", "password_salt", "need_update_password", "password_type", "last_change_password_time"}, false)
	} else {
		if isAdmin {
			err = object.ResetLdapPassword(targetUser, "", newPassword, c.GetAcceptLanguage())
		} else {
			err = object.ResetLdapPassword(targetUser, oldPassword, newPassword, c.GetAcceptLanguage())
		}
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk()
}

// CheckUserPassword
// @Title CheckUserPassword
// @router /check-user-password [post]
// @Tag User API
// @Success 200 {object} object.Userinfo The Response object
func (c *ApiController) CheckUserPassword() {
	var user object.User
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	/*
	 * Verified password with user as subject, if field ldap not empty,
	 * then `isPasswordWithLdapEnabled` is true
	 */
	_, err = object.CheckUserPassword(user.Owner, user.Name, user.Password, c.GetAcceptLanguage(), false, false, user.Ldap != "")
	if err != nil {
		c.ResponseError(err.Error())
	} else {
		c.ResponseOk()
	}
}

// GetSortedUsers
// @Title GetSortedUsers
// @Tag User API
// @Description
// @Param   owner     query    string  true        "The owner of users"
// @Param   sorter     query    string  true        "The DB column name to sort by, e.g., created_time"
// @Param   limit     query    string  true        "The count of users to return, e.g., 25"
// @Success 200 {array} object.User The Response object
// @router /get-sorted-users [get]
func (c *ApiController) GetSortedUsers() {
	// V5/N4: same crown-jewel roster as GetUsers, via the sorted variant —
	// gate app/M2M principals on the user-admin capability (humans + platform
	// apps pass; tenant apps denied).
	if !c.requireAppCapability(object.CapUserAdmin) {
		return
	}

	owner := c.Ctx.Input.Query("owner")
	sorter := c.Ctx.Input.Query("sorter")
	limit := util.ParseInt(c.Ctx.Input.Query("limit"))

	users, err := object.GetMaskedUsers(object.GetSortedUsers(owner, sorter, limit))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(users)
}

// GetUserCount
// @Title GetUserCount
// @Tag User API
// @Description
// @Param   owner     query    string  true        "The owner of users"
// @Param   isOnline     query    string  true        "The filter for query, 1 for online, 0 for offline, empty string for all users"
// @Success 200 {int} int The count of filtered users for an organization
// @router /get-user-count [get]
func (c *ApiController) GetUserCount() {
	// V5/Red#3: per-org user cardinality is a count oracle (incl the admin org).
	// Gate app/M2M principals on the user-admin capability; humans keep authz.
	if !c.requireAppCapability(object.CapUserAdmin) {
		return
	}

	owner := c.Ctx.Input.Query("owner")
	isOnline := c.Ctx.Input.Query("isOnline")

	var count int64
	var err error
	if isOnline == "" {
		count, err = object.GetUserCount(owner, "", "", "")
	} else {
		count, err = object.GetOnlineUserCount(owner, util.ParseInt(isOnline))
	}
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(count)
}

func (c *ApiController) RemoveUserFromGroup() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	groupName := c.Ctx.Request.Form.Get("groupName")

	organization, err := object.GetOrganization(util.GetId("admin", owner))
	if err != nil {
		return
	}
	item := object.GetAccountItemByName("Groups", organization)
	res, msg := object.CheckAccountItemModifyRule(item, c.IsAdmin(), c.GetAcceptLanguage())
	if !res {
		c.ResponseError(msg)
		return
	}

	affected, err := object.DeleteGroupForUser(util.GetId(owner, name), util.GetId(owner, groupName))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(affected)
}

// ImpersonateUser
// @Title ImpersonateUser
// @Tag User API
// @Description set impersonation user for current admin session
// @Param   username    formData   string  true        "The username to impersonate (owner/name)"
// @Success 200 {object} controllers.Response The Response object
// @router /impersonation-user [post]
func (c *ApiController) ImpersonateUser() {
	org, ok := c.RequireAdmin()
	if !ok {
		return
	}

	username := c.Ctx.Request.Form.Get("username")
	if username == "" {
		c.ResponseError(c.T("general:Missing parameter"))
		return
	}

	owner, _, err := util.GetOwnerAndNameFromIdWithError(username)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !(owner == org || org == conf.AdminOrg) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	targetUser, err := object.GetUser(username)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if targetUser == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), username))
		return
	}

	err = c.SetSession("impersonateUser", username)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.Ctx.SetCookie("impersonateUser", username, 0, "/")
	c.ResponseOk()
}

// ExitImpersonateUser
// @Title ExitImpersonateUser
// @Tag User API
// @Description clear impersonation info for current session
// @Success 200 {object} controllers.Response The Response object
// @router /exit-impersonation-user [post]
func (c *ApiController) ExitImpersonateUser() {
	_, ok := c.Ctx.Input.GetData("impersonating").(bool)
	if !ok {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	err := c.SetSession("impersonateUser", "")
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.Ctx.SetCookie("impersonateUser", "", -1, "/")
	c.ResponseOk()
}

// VerifyIdentification
// @Title VerifyIdentification
// @Tag User API
// @Description verify user's real identity using ID Verification provider
// @Param   owner     query    string  false  "The owner of the user (optional, defaults to logged-in user)"
// @Param   name      query    string  false  "The name of the user (optional, defaults to logged-in user)"
// @Param   provider  query    string  false  "The name of the ID Verification provider (optional, auto-selected if not provided)"
// @Success 200 {object} controllers.Response The Response object
// @router /verify-identification [post]
func (c *ApiController) VerifyIdentification() {
	owner := c.Ctx.Input.Query("owner")
	name := c.Ctx.Input.Query("name")
	providerName := c.Ctx.Input.Query("provider")

	// If user not specified, use logged-in user
	if owner == "" || name == "" {
		loggedInUser := c.GetSessionUsername()
		if loggedInUser == "" {
			c.ResponseError(c.T("general:Please login first"))
			return
		}
		var err error
		owner, name, err = util.GetOwnerAndNameFromIdWithError(loggedInUser)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	} else {
		// If user is specified, check if current user has permission to verify other users
		// Only admins can verify other users
		loggedInUser := c.GetSessionUsername()
		if loggedInUser != util.GetId(owner, name) && !c.IsAdmin() {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return
		}
	}

	user, err := object.GetUser(util.GetId(owner, name))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), util.GetId(owner, name)))
		return
	}

	if user.IdCard == "" || user.IdCardType == "" || user.RealName == "" {
		c.ResponseError(c.T("user:ID card information and real name are required"))
		return
	}

	if user.IsVerified {
		c.ResponseError(c.T("user:User is already verified"))
		return
	}

	var provider *object.Provider
	// If provider not specified, find suitable IDV provider from user's application
	if providerName == "" {
		application, err := object.GetApplicationByUser(user)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if application == nil {
			c.ResponseError(c.T("user:No application found for user"))
			return
		}

		// Find IDV provider from application
		idvProvider, err := object.GetIdvProviderByApplication(util.GetId(application.Owner, application.Name), "false", c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if idvProvider == nil {
			c.ResponseError(c.T("provider:No ID Verification provider configured"))
			return
		}
		provider = idvProvider
	} else {
		provider, err = object.GetProvider(providerName)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if provider == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The provider: %s does not exist"), providerName))
			return
		}

		if provider.Category != "ID Verification" {
			c.ResponseError(c.T("provider:Provider is not an ID Verification provider"))
			return
		}
	}

	idvProvider := object.GetIdvProviderFromProvider(provider)
	if idvProvider == nil {
		c.ResponseError(c.T("provider:Failed to initialize ID Verification provider"))
		return
	}

	verified, err := idvProvider.VerifyIdentity(user.IdCardType, user.IdCard, user.RealName)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !verified {
		c.ResponseError(c.T("user:Identity verification failed"))
		return
	}

	// Set IsVerified to true upon successful verification
	user.IsVerified = true
	_, err = object.UpdateUser(user.GetId(), user, []string{"is_verified"}, false)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(user.RealName)
}

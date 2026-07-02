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

// Service-account HTTP surface: create / list / rotate-key / delete an agent's
// IAM identity, org-scoped, under /v1/iam/service-accounts.
//
// Authorization mirrors the hk- key-mint primitive (resolveTargetUserForKeys):
// creating a service account and minting its key is the same trust boundary as
// minting a user's hk- key — it produces an org-billing credential — so it
// shares the SAME fail-secure gate:
//
//   - an app/<name> confidential client (e.g. hanzo-console) may act on any
//     org ONLY if allowlisted in IAM_KEY_MINT_ALLOWED_APPS (CapKeyMint). A
//     non-allowlisted app is rejected — this closes the blanket "every app is
//     global admin" hole for cross-tenant SA provisioning.
//   - a human caller may act ONLY within an org they administer (real
//     global-admin USER, or an org admin of the target org).
//   - anonymous → 401.

package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/hanzoai/beego/v2/core/utils/pagination"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// serviceAccountRequest is the create-service-account body.
type serviceAccountRequest struct {
	// Organization is the owning org. The SA is org-scoped: every token minted
	// from its key carries owner==organization.
	Organization string `json:"organization"`
	// Name is the agent handle. It may be the bare agent segment (e.g.
	// "slackbot"), which is normalized to the canonical <org>-<agent> handle,
	// or the already-canonical "<org>-<agent>" form.
	Name string `json:"name"`
	// AgentRef optionally back-references the agent record this SA embodies.
	AgentRef string `json:"agentRef"`
}

// authorizeServiceAccountAdmin enforces the caller→org authorization binding for
// service-account mutation and returns the resolved caller username. It writes
// the error response and returns ("", false) on denial.
//
// Identical trust boundary to resolveTargetUserForKeys, generalized to an ORG
// (a service account has no pre-existing target user to bind to at create time):
//
//   - app caller  → must be CapKeyMint-allowlisted (fail-secure).
//   - human caller→ must be a real global-admin USER, or an admin of `org`.
func (c *ApiController) authorizeServiceAccountAdmin(org string) (string, bool) {
	caller := c.GetSessionUsername()
	if caller == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return "", false
	}

	if object.IsAppUser(caller) {
		if !object.AppAllowedForCapability(caller, object.CapKeyMint) {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return "", false
		}
		return caller, true
	}

	// Human caller. c.IsAdmin()/isGlobalAdmin treat every app as global admin,
	// but caller here is a human, so it is safe. A real global admin may act on
	// any org; otherwise the caller must be an admin whose OWN org is `org`.
	u := c.getCurrentUser()
	if u == nil {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return "", false
	}
	if u.IsGlobalAdmin() {
		return caller, true
	}
	if u.IsAdmin && u.Owner == org {
		return caller, true
	}
	c.ResponseError(c.T("auth:Unauthorized operation"))
	return "", false
}

// resolveServiceAccountName maps a (org, name) request pair to the canonical
// <org>-<agent> handle. A bare agent segment is prefixed; an already-canonical
// name is kept as-is. Returns "" if the resulting name is malformed.
func resolveServiceAccountName(org, name string) string {
	if name == "" {
		return ""
	}
	canonical := name
	if !isCanonicalForOrg(org, name) {
		canonical = object.ServiceAccountName(org, name)
	}
	if object.CheckServiceAccountName(canonical) != "" {
		return ""
	}
	return canonical
}

// isCanonicalForOrg reports whether name already carries the "<org>-" prefix
// with a non-empty agent segment.
func isCanonicalForOrg(org, name string) bool {
	prefix := org + "-"
	return len(name) > len(prefix) && name[:len(prefix)] == prefix
}

// CreateServiceAccount
// @Title CreateServiceAccount
// @Tag ServiceAccount API
// @Description Create an agent/bot service-account identity in an org and mint
//
//	its first API key. Returns the raw access key + secret EXACTLY ONCE; only the
//	argon2id hash of the secret is stored. The account authenticates ONLY by this
//	key (no password) and its actions are attributed to <org>/<org-agent>.
//
// @Param   body  body  serviceAccountRequest  true  "organization, name, agentRef"
// @Success 200 {object} controllers.Response The Response object
// @router /service-accounts [post]
func (c *ApiController) CreateServiceAccount() {
	var req serviceAccountRequest
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if req.Organization == "" {
		c.ResponseError(c.T("general:Missing parameter"), "organization is required")
		return
	}

	if _, ok := c.authorizeServiceAccountAdmin(req.Organization); !ok {
		return
	}

	name := resolveServiceAccountName(req.Organization, req.Name)
	if name == "" {
		c.ResponseError(c.T("general:Missing parameter"), "a valid name is required")
		return
	}

	sa, accessKey, rawSecret, err := object.CreateServiceAccount(req.Organization, name, req.AgentRef, c.IsAdmin())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Return the raw credential ONCE. accessKey is the lookup handle presented
	// as the OAuth grant `access_key`; accessSecret is the one-time secret. After
	// this response the secret is unrecoverable (only its argon2id hash persists).
	c.ResponseOk(map[string]interface{}{
		"owner":        sa.Owner,
		"name":         sa.Name,
		"type":         sa.Type,
		"agentRef":     sa.Tag,
		"accessKey":    accessKey,
		"accessSecret": rawSecret,
	})
}

// GetServiceAccounts
// @Title GetServiceAccounts
// @Tag ServiceAccount API
// @Description List the service accounts in an org. Returns names + metadata
//
//	only — NEVER secrets (access key/secret are masked; the hash never
//	serializes).
//
// @Param   organization  query  string  true  "The owning organization"
// @Success 200 {array} object.User The Response object
// @router /service-accounts [get]
func (c *ApiController) GetServiceAccounts() {
	org := c.Ctx.Input.Query("organization")
	if org == "" {
		c.ResponseError(c.T("general:Missing parameter"), "organization is required")
		return
	}

	if _, ok := c.authorizeServiceAccountAdmin(org); !ok {
		return
	}

	sas, err := object.ListServiceAccounts(org)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	if limit == "" || page == "" {
		c.ResponseOk(sas)
		return
	}

	// Paginate the already-masked, already-org-scoped slice in memory. The set
	// of service accounts per org is small; a dedicated count query is overkill.
	count := int64(len(sas))
	paginator := pagination.NewPaginator(c.Ctx.Request, util.ParseInt(limit), count)
	start := paginator.Offset()
	end := start + util.ParseInt(limit)
	if start > len(sas) {
		start = len(sas)
	}
	if end > len(sas) {
		end = len(sas)
	}
	c.ResponseOk(sas[start:end], count)
}

// RotateServiceAccountKey
// @Title RotateServiceAccountKey
// @Tag ServiceAccount API
// @Description Rotate (mint a new) API key for a service account, invalidating
//
//	the prior key immediately. Returns the new raw access key + secret EXACTLY
//	ONCE.
//
// @Param   name          path   string  true  "The service account name (<org>-<agent>)"
// @Param   organization  query  string  true  "The owning organization"
// @Success 200 {object} controllers.Response The Response object
// @router /service-accounts/:name/keys [post]
func (c *ApiController) RotateServiceAccountKey() {
	sa, ok := c.loadServiceAccountForMutation()
	if !ok {
		return
	}

	accessKey, rawSecret, err := object.MintServiceAccountKey(sa, c.IsAdmin())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(map[string]interface{}{
		"owner":        sa.Owner,
		"name":         sa.Name,
		"accessKey":    accessKey,
		"accessSecret": rawSecret,
	})
}

// DeleteServiceAccount
// @Title DeleteServiceAccount
// @Tag ServiceAccount API
// @Description Delete (revoke) a service account.
// @Param   name          path   string  true  "The service account name (<org>-<agent>)"
// @Param   organization  query  string  true  "The owning organization"
// @Success 200 {object} controllers.Response The Response object
// @router /service-accounts/:name [delete]
func (c *ApiController) DeleteServiceAccount() {
	sa, ok := c.loadServiceAccountForMutation()
	if !ok {
		return
	}
	c.Data["json"] = wrapActionResponse(object.DeleteServiceAccount(sa))
	c.ServeJSON()
}

// loadServiceAccountForMutation resolves the :name path param within the
// `organization` query org, authorizes the caller, and confirms the row is a
// service account. Writes the error response and returns (nil,false) on any
// failure. Shared by rotate + delete.
func (c *ApiController) loadServiceAccountForMutation() (*object.User, bool) {
	org := c.Ctx.Input.Query("organization")
	name := c.Ctx.Input.Param(":name")
	if org == "" || name == "" {
		c.ResponseError(c.T("general:Missing parameter"), "organization and name are required")
		return nil, false
	}

	if _, ok := c.authorizeServiceAccountAdmin(org); !ok {
		return nil, false
	}

	sa, err := object.GetServiceAccount(org, name)
	if err != nil {
		c.ResponseError(err.Error())
		return nil, false
	}
	if sa == nil {
		c.ResponseError(fmt.Sprintf("the service account %q does not exist in organization %q", name, org))
		return nil, false
	}
	return sa, true
}

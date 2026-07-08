// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package controllers

import (
	"encoding/json"

	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// approval.go — the waitlist approval control plane.
//
// Customer access is gated by ONE authoritative user property
// (object.ApprovalStatusProperty): a self-service signup lands "pending" (on the
// waitlist, no access), an admin flips it to "approved". These endpoints are what
// admin.hanzo.ai calls to run the queue. Authorization: a GLOBAL admin sees/acts on
// every org; an ORG admin (IsAdmin within their own org) sees/acts only on their own
// org's users. Everything here is fail-secure — a non-admin gets Unauthorized.

// canAdministerOrg reports whether the calling session may view/approve users in
// `org`. Global admins: any org. Org admins: only their own org. Returns the
// caller for logging; ok=false means the caller already got an error response.
func (c *ApiController) canAdministerOrg(org string) (*object.User, bool) {
	isGlobal, user := c.isGlobalAdmin()
	if isGlobal {
		return user, true
	}
	if user == nil || !user.IsAdmin || user.Owner != org {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return user, false
	}
	return user, true
}

// GetPendingUsers lists users awaiting approval (the ranked waitlist's IAM view).
//
// Endpoint: GET /v1/iam/get-pending-users?owner=<org>
//   - global admin: omit owner to list pending across ALL orgs, or pass one to scope.
//   - org admin: owner is forced to the caller's own org.
//
// Response: masked users whose approvalStatus == "pending".
func (c *ApiController) GetPendingUsers() {
	owner := c.Ctx.Input.Query("owner")

	isGlobal, caller := c.isGlobalAdmin()
	if !isGlobal {
		if caller == nil || !caller.IsAdmin {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return
		}
		owner = caller.Owner // org admins are scoped to their own org
	}

	var users []*object.User
	var err error
	if owner == "" {
		users, err = object.GetGlobalUsers()
	} else {
		users, err = object.GetUsers(owner)
	}
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	pending := make([]*object.User, 0, len(users))
	for _, u := range users {
		if u.Properties != nil && u.Properties[object.ApprovalStatusProperty] == object.ApprovalPending {
			pending = append(pending, u)
		}
	}

	masked, err := object.GetMaskedUsers(pending)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(masked, len(masked))
}

// ApproveUser flips a pending user to approved, unlocking customer access.
//
// Endpoint: POST /v1/iam/approve-user   body: {"id":"<owner>/<name>"}
// Auth: global admin (any org) or org admin (own org only). Idempotent.
func (c *ApiController) ApproveUser() {
	var req struct {
		Id string `json:"id"`
	}
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if req.Id == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": id")
		return
	}

	owner, _, err := util.GetOwnerAndNameFromIdWithError(req.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if _, ok := c.canAdministerOrg(owner); !ok {
		return
	}

	user, err := object.GetUser(req.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(c.T("general:The user: %s doesn't exist"))
		return
	}

	user.SetApprovalStatus(object.ApprovalApproved)
	affected, err := object.UpdateUserForAllFields(req.Id, user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(map[string]any{"approved": true, "updated": affected, "id": req.Id})
}

// RejectUser marks a pending user rejected (keeps them off the app; a distinct
// terminal state from pending so the queue can filter them out).
//
// Endpoint: POST /v1/iam/reject-user   body: {"id":"<owner>/<name>"}
// Auth: same as ApproveUser.
func (c *ApiController) RejectUser() {
	var req struct {
		Id string `json:"id"`
	}
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if req.Id == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": id")
		return
	}
	owner, _, err := util.GetOwnerAndNameFromIdWithError(req.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if _, ok := c.canAdministerOrg(owner); !ok {
		return
	}
	user, err := object.GetUser(req.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(c.T("general:The user: %s doesn't exist"))
		return
	}
	user.SetApprovalStatus("rejected")
	affected, err := object.UpdateUserForAllFields(req.Id, user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(map[string]any{"rejected": true, "updated": affected, "id": req.Id})
}

// GetApprovalStatus returns the caller's own approval status — the gate/SPA calls
// this to decide "show the app" vs "show the waitlist".
//
// Endpoint: GET /v1/iam/approval-status
func (c *ApiController) GetApprovalStatus() {
	username := c.GetSessionUsername()
	if username == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}
	user, err := object.GetUser(username)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(c.T("general:The user: %s doesn't exist"))
		return
	}
	status := object.ApprovalApproved
	if user.Properties != nil {
		if s, ok := user.Properties[object.ApprovalStatusProperty]; ok && s != "" {
			status = s
		}
	}
	c.ResponseOk(map[string]any{
		"approved": user.IsApproved(),
		"status":   status,
	})
}

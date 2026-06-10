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

// Defense-in-depth guard for the by-attribute endpoint's
// client_credentials discriminator. The synthetic application-user
// minted by object.GetClientCredentialsToken
// (object/token_oauth.go:1044-1049) carries User.Type=="application".
// Several internal services use that field as a "this is a service
// principal" signal — most notably controllers/users_by_attribute.go's
// defaultResolveServiceClaims.
//
// Without this guard, a tenant admin could call POST /add-user with
// a body carrying `Type: "application"`, password-grant the resulting
// user, and pass any Type-based service discriminator. The guard
// closes that hole at the write boundary so it cannot be reached by
// any later reader that checks Type alone.
//
// The only legitimate writer of Type=="application" is the bootstrap
// path inside the built-in org (where IAM itself seeds its own admin
// app's nullUser). We allow it ONLY for that org.

package controllers

import (
	"net/http"

	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
)

// applicationUserType is the magic literal that GetClientCredentialsToken
// stamps into the synthetic user's Type field. Centralized here so all
// readers/writers reference the same constant.
const applicationUserType = "application"

// resolveTypeGuardCaller is the seam for "who is the calling user?".
// Production reads via getCurrentUser (session-backed). Tests substitute
// a deterministic value to exercise the policy branches without standing
// up a session store + xorm engine.
var resolveTypeGuardCaller = defaultResolveTypeGuardCaller

func defaultResolveTypeGuardCaller(c *ApiController) *object.User {
	return c.getCurrentUser()
}

// rejectApplicationTypePromotion returns true if the request is allowed
// to proceed (i.e. the body's Type is benign, OR the caller is an
// authorized bootstrap-org admin). Returns false AFTER writing a 403
// response to the controller — in that case the caller MUST return.
//
// The check is intentionally strict: ONLY a user whose own Owner is
// conf.AdminOrg may set Type=="application". IAM's semantics already
// treat the entire bootstrap (AdminOrg) tenant as the global-admin
// surface (see object/user.go::IsGlobalAdmin == "Owner == AdminOrg"),
// so org membership IS the privilege. Tenant org admins (any non-
// AdminOrg tenant) are rejected. Anonymous / unauthenticated callers
// are rejected.
//
// Per the threat model in users_by_attribute.go: the goal is to keep
// the synthetic-application-user shape exclusive to client_credentials
// token minting. Any human-created path producing the same shape
// becomes an impersonation oracle.
func rejectApplicationTypePromotion(c *ApiController, u *object.User) bool {
	if u == nil || u.Type != applicationUserType {
		return true
	}
	caller := resolveTypeGuardCaller(c)
	if caller != nil && caller.Owner == conf.AdminOrg {
		return true
	}
	c.Ctx.Output.SetStatus(http.StatusForbidden)
	c.ResponseError("forbidden: User.Type=\"application\" is reserved for the client_credentials grant; only the IAM bootstrap admin may set it")
	return false
}

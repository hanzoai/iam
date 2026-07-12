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

package controllers

import "github.com/hanzoai/iam/object"

// requireAppCapability is the single choke point that revokes the legacy
// "every confidential-client credential is a global admin" privilege for
// sensitive mutations.
//
// If the current request principal is an app ("app/<name>", minted by the
// client_credentials grant), it may proceed ONLY when <name> is in the
// fail-secure env allowlist for cap (IAM_PASSWORD_ADMIN_APPS,
// IAM_USER_ADMIN_APPS, IAM_APP_ADMIN_APPS). Otherwise the request is rejected
// with "Unauthorized operation".
//
// Human principals (interactive sessions and forwarded user JWTs) are NOT
// affected — they remain governed by the per-endpoint authorization
// (self / org IsAdmin / real global-admin USER via User.IsSuperAdmin()) plus
// Casbin. This keeps the legitimate console password reset, self-service
// password change (verification-code path), and real global-admin operations
// working untouched.
//
// Returns true if the caller may proceed; false (and writes the error
// response) if the app principal is not allowlisted for cap.
func (c *ApiController) requireAppCapability(cap object.AppAdminCapability) bool {
	username := c.GetSessionUsername()
	if object.IsAppUser(username) && !object.AppAllowedForCapability(username, cap) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return false
	}
	return true
}

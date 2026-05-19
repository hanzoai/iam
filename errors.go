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

package iam

import "errors"

// Typed errors. Callers branch via errors.Is.
//
// Identity input model: every method that takes a string identifier
// (userID, orgID, roleName, perm) operates within the actor scope
// derived from the caller's validated bearer-auth Claims. Cross-org
// reads return ErrCrossOrg, not ErrUserNotFound — the latter would
// allow an attacker to enumerate users in other orgs.
var (
	ErrTokenMissing  = errors.New("iam: authentication required")
	ErrTokenInvalid  = errors.New("iam: invalid token")
	ErrTokenExpired  = errors.New("iam: token expired")
	ErrTokenRevoked  = errors.New("iam: token revoked")
	ErrTokenAudience = errors.New("iam: token audience mismatch")
	ErrUserNotFound  = errors.New("iam: user not found")
	ErrOrgNotFound   = errors.New("iam: org not found")
	ErrCrossOrg      = errors.New("iam: cross-org access forbidden")
)

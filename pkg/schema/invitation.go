// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Invitation is a pending organization-membership invite (v1
// `invitation`, v2 kind "invitations"). One row grants a bounded number of
// signups against a shared or per-recipient Code: the code is a literal, or a
// pattern when IsRegexp is set, and each successful signup increments UsedCount
// up to Quota. The optional Application, Username, Email, and Phone pins
// constrain who may redeem it; SignupGroup places a redeemer into a group on
// join. State ("Active" vs. suspended) gates redemption and DefaultCode is the
// fallback code surfaced in the signup link. Field-complete against the v1 row
// so no code, quota, or recipient pin is lost on migration. Identity is the
// (Owner, Name) pair; the orm string key is "owner/name".
type Invitation struct {
	orm.Model[Invitation]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime" orm:"index"`
	UpdatedTime string `json:"updatedTime"`
	DisplayName string `json:"displayName"`

	Code      string `json:"code" orm:"index"`
	IsRegexp  bool   `json:"isRegexp"`
	Quota     int    `json:"quota"`
	UsedCount int    `json:"usedCount"`

	Application string `json:"application"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`

	SignupGroup string `json:"signupGroup"`
	DefaultCode string `json:"defaultCode"`

	State string `json:"state"`
}

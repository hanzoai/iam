// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"encoding/json"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// GET/PUT /v1/iam/consent — the account-canonical data-sharing consent: the ONE
// place a user's choice lives. The hanzo.id signup asks it, the browser extension
// reads/writes it, and hanzo.ai edits it — all through here. It rides the SAME
// self-scoped preferences blob as update-preferences (preferencesKey → "consent"),
// so there is one store, one merge, one source of truth (no parallel table to drift).
//
// SELF-SCOPED: the target is ALWAYS the caller (callerOf), never a body field.
//
// Two switches, privacy-first defaults when unset:
//
//	insights      default TRUE  — anonymous product usage (no query/answer text).
//	shareTraining default FALSE — OPT-IN to contribute the user's own data to
//	                              train Hanzo's open models.
const PathConsent = "/v1/iam/consent"

// consentKey nests the consent object inside the preferences blob.
const consentKey = "consent"

type consentView struct {
	Insights      bool `json:"insights"`
	ShareTraining bool `json:"shareTraining"`
}

// consentOf reads consent out of a preferences JSON blob, applying the defaults
// for a first-ever read (insights on, training off).
func consentOf(prefs string) consentView {
	v := consentView{Insights: true, ShareTraining: false}
	if prefs == "" {
		return v
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(prefs), &m) != nil {
		return v
	}
	if raw, ok := m[consentKey]; ok {
		_ = json.Unmarshal(raw, &v)
	}
	return v
}

// getConsentHandler returns the calling person's own privacy and communication
// choices. Somebody who has never set them gets the defaults rather than
// nothing, so a consent screen always has something to show.
func getConsentHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "please sign in first")
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil || user == nil {
			return httpx.Err(c, "server_error")
		}
		return httpx.Ok(c, consentOf(user.Properties[preferencesKey]))
	}
}

// putConsentHandler records the calling person's privacy and communication
// choices. Only their own — there is no way to set consent for somebody else.
//
// It merges rather than replaces, so saving a consent screen never discards a
// preference some other screen set at the same moment.
func putConsentHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "please sign in first")
		}
		var in consentView
		if err := json.Unmarshal(c.Fiber().Body(), &in); err != nil {
			return httpx.Err(c, "consent must be a JSON object")
		}
		if _, err := updateUser(ctx, db, owner, name, func(u *schema.User) error {
			merged := map[string]json.RawMessage{}
			if blob := u.Properties[preferencesKey]; blob != "" {
				_ = json.Unmarshal([]byte(blob), &merged)
			}
			cj, err := json.Marshal(in)
			if err != nil {
				return err
			}
			merged[consentKey] = cj
			out, err := json.Marshal(merged)
			if err != nil {
				return err
			}
			if u.Properties == nil {
				u.Properties = map[string]string{}
			}
			u.Properties[preferencesKey] = string(out)
			u.UpdatedTime = provisionNow()
			return nil
		}); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, in)
	}
}

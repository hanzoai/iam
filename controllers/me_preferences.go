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

// me_preferences.go — POST /v1/iam/update-preferences.
//
// The ONE account-backed store for cross-product, cross-device user
// customizations (onboarding-completed flag, consent choice, pinned
// favorites, layout, …). The console's PreferencesProvider reads these
// from the account's `properties["hanzo.preferences"]` (a JSON blob) and
// write-through-persists partial updates here.
//
// SECURITY (self-scoped, never the body):
//   - The target user is ALWAYS the signed-in principal (RequireSignedInUser,
//     the same JWT/session used by /v1/iam/get-account) — never a name or org
//     carried in the request. A caller can only ever write its OWN preferences.
//   - The write is column-scoped to "properties" (object.UpdateUser cols), so
//     it touches only the preferences blob, never credentials or roles.
//
// MERGE SEMANTICS: top-level keys are shallow-merged onto the stored object,
// so concurrent products/devices setting DIFFERENT keys don't clobber each
// other; a key present in the patch overwrites that one key only. The merged
// object is returned so the caller's local view keeps every other product's
// keys.

package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/hanzoai/iam/object"
)

// preferencesKey is the User.Properties entry holding the cross-product
// preferences JSON blob. It is the backend half of the console contract
// (src/lib/products/preferences.tsx PREFS_PROPERTY) — keep the two in lockstep.
const preferencesKey = "hanzo.preferences"

// preferencesMaxBytes caps the serialized merged blob so a runaway client can't
// grow the properties column without bound. 64 KiB is far above any real
// preference set (flags, a currency, a handful of pinned ids).
const preferencesMaxBytes = 64 * 1024

// mergePreferences shallow-merges a JSON `patch` object onto the `existing`
// preferences JSON string and returns the merged JSON plus the merged map. It is
// pure (no session, no DB) so the merge invariants are unit-testable directly:
//
//   - a patch key overwrites ONLY that top-level key; every other stored key
//     survives (cross-device/product non-clobber);
//   - an absent/blank/corrupt `existing` is treated as an empty object, so a
//     first write still lands;
//   - a patch that is not a JSON object is rejected (fail closed);
//   - the merged blob is size-capped.
func mergePreferences(existing string, patch []byte) (string, map[string]json.RawMessage, error) {
	patchMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(patch, &patchMap); err != nil {
		return "", nil, fmt.Errorf("preferences must be a JSON object: %w", err)
	}

	merged := map[string]json.RawMessage{}
	if existing != "" {
		// A corrupt stored blob is treated as empty rather than failing the write —
		// the new patch still persists and self-heals the entry.
		_ = json.Unmarshal([]byte(existing), &merged)
	}
	for k, v := range patchMap {
		merged[k] = v
	}

	out, err := json.Marshal(merged)
	if err != nil {
		return "", nil, err
	}
	if len(out) > preferencesMaxBytes {
		return "", nil, fmt.Errorf("preferences exceed maximum size of %d bytes", preferencesMaxBytes)
	}
	return string(out), merged, nil
}

// UpdatePreferences
// @Title UpdatePreferences
// @Tag Account API
// @Description shallow-merge a partial preferences object onto the signed-in
// user's account (self-scoped, cross-device). Returns the merged preferences.
// @Param body body object true "partial preferences object (top-level keys shallow-merged)"
// @Success 200 {object} controllers.Response The merged preferences in `data`
// @router /update-preferences [post]
func (c *ApiController) UpdatePreferences() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	mergedJSON, merged, err := mergePreferences(user.Properties[preferencesKey], c.Ctx.Input.RequestBody)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user.Properties == nil {
		user.Properties = map[string]string{}
	}
	user.Properties[preferencesKey] = mergedJSON

	// Column-scoped write: only the properties blob is touched.
	if _, err := object.UpdateUser(user.GetId(), user, []string{"properties"}, false); err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(merged)
}

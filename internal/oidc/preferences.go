// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"encoding/json"
	"fmt"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// POST /v1/iam/update-preferences — the ONE account-backed store for cross-product,
// cross-device user customizations (onboarding-completed flag, theme, pinned
// favorites, …). The console's PreferencesProvider reads these from the account's
// Properties["hanzo.preferences"] JSON blob and write-through-persists partial updates
// here. Ported from the v1 me_preferences.go contract.
//
// SELF-SCOPED (never the body): the target user is ALWAYS the caller resolved from its
// session/bearer (callerOf) — never a name/org in the request — so a caller can only
// ever write its OWN preferences. MERGE: top-level keys are shallow-merged onto the
// stored object, so concurrent products/devices setting DIFFERENT keys don't clobber
// each other; the merged object is returned so the caller keeps every other key.

// PathPreferences (canonical.go) is the self-preferences endpoint.

// preferencesKey is the User.Properties entry holding the cross-product preferences
// JSON blob — the backend half of the console contract (PREFS_PROPERTY); keep in
// lockstep.
const preferencesKey = "hanzo.preferences"

// preferencesMaxBytes caps the serialized merged blob so a runaway client can't grow
// the properties column without bound.
const preferencesMaxBytes = 64 * 1024

// updatePreferencesHandler saves the calling person's own settings and returns
// the full set afterwards. Send only the settings you are changing — the rest
// are kept, so two screens can save at once without one undoing the other.
func updatePreferencesHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "please sign in first")
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		if user == nil {
			return httpx.Err(c, "the user does not exist")
		}

		// Merge under the row lock against the FRESH stored blob (updateUser): a
		// concurrent product/device setting a DIFFERENT top-level key is preserved (the
		// merge now reads the current value, not a snapshot), and the lockout counter is
		// never clobbered by this full-row write.
		body := c.Fiber().Body()
		var merged map[string]json.RawMessage
		if _, err := updateUser(ctx, db, owner, name, func(u *schema.User) error {
			mergedJSON, m, err := mergePreferences(u.Properties[preferencesKey], body)
			if err != nil {
				return err
			}
			if u.Properties == nil {
				u.Properties = map[string]string{}
			}
			u.Properties[preferencesKey] = mergedJSON
			u.UpdatedTime = provisionNow()
			merged = m
			return nil
		}); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, merged)
	}
}

// mergePreferences shallow-merges a JSON `patch` object onto the `existing`
// preferences JSON string, returning the merged JSON plus the merged map. Pure (no
// session, no DB): a patch key overwrites ONLY that top-level key (every other stored
// key survives); an absent/blank/corrupt `existing` is an empty object (a first write
// still lands and self-heals); a non-object patch is rejected; the blob is size-capped.
func mergePreferences(existing string, patch []byte) (string, map[string]json.RawMessage, error) {
	patchMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(patch, &patchMap); err != nil {
		return "", nil, fmt.Errorf("preferences must be a JSON object: %w", err)
	}

	merged := map[string]json.RawMessage{}
	if existing != "" {
		_ = json.Unmarshal([]byte(existing), &merged) // corrupt stored blob → treated as empty
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

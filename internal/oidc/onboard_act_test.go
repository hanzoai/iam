// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// A delegated token (as(), naming its org key in `act`) acts for the person it
// names, and the person did not ask: it founds no org for them and takes no key
// in their name, and changes nothing of their account. The person's own token
// still does.
func TestOnboard_ADelegatedTokenFoundsNothing(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "hanzo", "alice", "ext-alice")
	seedActKey(t, db, "hanzo", "op", "sk-live-optoken", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-optoken", "?id=hanzo/alice"))
	if resp.StatusCode != 200 {
		t.Fatalf("as(): %d %s", resp.StatusCode, body)
	}
	delegated, _ := dataMap(t, body)["accessToken"].(string)

	req := jsonReq("POST", PathOnboard, map[string]any{"name": "Taken For Her"})
	req.Header.Set("Authorization", "Bearer "+delegated)
	resp, raw := do(t, app, req)
	if resp.StatusCode != 401 {
		t.Fatalf("a delegated token founding an org: %d %s, want 401", resp.StatusCode, raw)
	}
	if org, _ := store.GetOrganizationByName(ctx, db, "taken-for-her"); org != nil {
		t.Fatalf("an org was founded for the person a delegated token named: %+v", org)
	}
	// The account surface writes refuse it the same way, by the same resolution.
	if owner, name, ok := callerFrom(ctx, db, "", delegated); ok {
		t.Fatalf("a delegated token resolved as the account holder %s/%s", owner, name)
	}
	if owner, _, _, ok := accountOf(ctx, db, "", delegated); !ok || owner != "hanzo" {
		t.Fatalf("a delegated token no longer reads as the person it names: %q %v", owner, ok)
	}
}

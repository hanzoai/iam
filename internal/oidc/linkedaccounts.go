// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"maps"
	"slices"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// GET /v1/iam/linked-accounts — the caller's linked social/OAuth identities.
//
// schema.User has NO single "linkedIdentities" array; a linked identity is stored as
// the connector's own column (User.GitHub, User.Google, …) holding the federated
// subject — the legacy data model. So the linked accounts ARE those per-connector
// columns that are set; this returns [{provider, subject}] for each non-empty one.
// Each item carries only the subject string (the schema stores no per-link display
// name / avatar / linkedAt), so a richer per-link shape is not available from iam.
// Self-scoped: resolved from the caller (callerOf), never the request.

// PathLinkedAccounts is the canonical linked-identities endpoint.
const PathLinkedAccounts = "/v1/iam/linked-accounts"

// linkedAccount is one linked social/OAuth identity.
type linkedAccount struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

// linkedAccountsHandler returns the sign-in identities linked to the calling
// person's account — every provider they can currently sign in with. It is what
// a security page lists next to the option to disconnect one.
func linkedAccountsHandler(db orm.DB) zip.Handler {
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
		return httpx.Ok(c, linkedAccountsOf(user))
	}
}

// linkedAccountsOf lists a user's federated subjects, in provider order, from the
// one list of connectors federation signs in with (schema.Connectors).
func linkedAccountsOf(u *schema.User) []linkedAccount {
	out := []linkedAccount{}
	for _, provider := range slices.Sorted(maps.Keys(schema.Connectors)) {
		if s := *schema.Connectors[provider](u); s != "" {
			out = append(out, linkedAccount{Provider: provider, Subject: s})
		}
	}
	return out
}

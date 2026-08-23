// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// Canonical noun addresses for the native endpoints that were spelled as
// verb-nouns.
//
// A path segment names a THING, and the HTTP method says what is being done to
// it. `POST /v1/iam/send-verification-code` says the verb twice and the noun
// once; `POST /v1/iam/verification-codes` says each exactly once. The verb-noun
// spellings came in with the entity store this service replaced, and they are
// what a customer reads in `hanzo iam --help`, in every generated SDK method
// name and on every docs page — so they are a customer-facing surface, not an
// internal detail.
//
// Every constant below is the address the published document declares. The old
// spelling stays REACHABLE — same handler, registered twice by alias() — so no
// consumer pinned to it breaks; it is simply not what anything teaches. When the
// last pinned consumer moves, the Legacy* half of a pair is deleted and nothing
// else changes.
const (
	PathAccount           = "/v1/iam/account"            // legacy: get-account
	PathAuthApplication   = "/v1/iam/auth/application"   // legacy: get-app-login
	PathPreferences       = "/v1/iam/preferences"        // legacy: update-preferences
	PathVerificationCodes = "/v1/iam/verification-codes" // legacy: send-verification-code
	PathTokensIssue       = "/v1/iam/tokens/issue"       // legacy: issue-user-token
	PathKeysMint          = "/v1/iam/keys/mint"          // legacy: mint-user-keys
	PathKeysRevoke        = "/v1/iam/keys/revoke"        // legacy: revoke-user-keys
)

// The verb-noun spellings these replaced. Kept reachable, taught nowhere.
const ()

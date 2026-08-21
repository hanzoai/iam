// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// Canonical noun addresses for the front-door endpoints that were spelled as
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
// Every constant below is the address the published document declares, and now
// the only one served. The verb-noun spellings were kept reachable while
// consumers moved; they are gone, so there is one address per thing and no
// second spelling for a reader to find, an SDK to generate or a CLI to teach.
const (
	PathAccount           = "/v1/iam/account"
	PathAuthApplication   = "/v1/iam/auth/application"
	PathPreferences       = "/v1/iam/preferences"
	PathVerificationCodes = "/v1/iam/verification-codes"
	PathTokensIssue       = "/v1/iam/tokens/issue"
	PathKeysMint          = "/v1/iam/keys/mint"
	PathKeysRevoke        = "/v1/iam/keys/revoke"
)

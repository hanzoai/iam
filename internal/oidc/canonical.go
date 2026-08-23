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
// Every constant below is the address the published document declares. The old
// spelling stays REACHABLE — one handler value at both addresses — so no consumer
// pinned to it breaks; it is simply not what anything teaches. When the last
// pinned consumer moves, the Legacy* half of a pair is deleted and nothing else
// changes.
const (
	PathAccount           = "/v1/iam/account"            // legacy: get-account
	PathAuthApplication   = "/v1/iam/auth/application"   // legacy: get-app-login
	PathPreferences       = "/v1/iam/preferences"        // legacy: update-preferences
	PathVerificationCodes = "/v1/iam/verification-codes" // legacy: send-verification-code
	PathTokensIssue       = "/v1/iam/tokens/issue"       // legacy: issue-user-token
	// PathUserKeys is the key a user holds. POST mints one and DELETE takes it
	// away — the same shape a service account's key already has
	// (/v1/iam/service-accounts/{name}/keys), so one identity kind is not
	// addressed differently from the other. The target is IN the address, not a
	// ?id= the address has to be told about, and WHICH class of key stays a
	// ?type= field, because the two classes differ in what they may do and not in
	// what you call to get one.
	PathUserKeys = "/v1/iam/users/:owner/:name/keys" // legacy: mint-user-keys, revoke-user-keys
)

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package model exposes the iam core's identity value types to external feature
// modules (hanzoiam/*) WITHOUT leaking internal/. They are ALIASES of the core
// schema, so a module and the core share ONE type — no mapping, no drift.
package model

import "github.com/hanzoai/iam/pkg/schema"

type (
	User         = schema.User
	Application  = schema.Application
	Organization = schema.Organization
	Cert         = schema.Cert
	Provider     = schema.Provider

	// OrgRef is the (org, role) membership reference a token carries in its `orgs`
	// claim. Exported here so a consumer (cloud) reads the tenancy set off a v2
	// token WITHOUT importing the dead iam-v1 — the same shape and JSON tags, one
	// canonical definition (schema.OrgRef), no drift.
	OrgRef = schema.OrgRef

	// Project is the org-scoped work container (owner-scoped by (Owner, Name),
	// where Owner is the owning organization). Exported here so an embedder (cloud)
	// reads/writes the SAME project rows the registered /v1/iam/projects surface serves
	// via pkg/store — one canonical definition (schema.Project), no platform-local
	// clone, replacing the dead iam-v1 object.Project.
	Project = schema.Project

	// Consent is a user's data-sharing answers, and Answer is the tri-state of one
	// of them. Exported so a consumer outside this module (cloud, and any data path
	// that must not act without an answer) reads the SAME record through the SAME
	// predicate — Consent.MayTrain — instead of re-deriving what "granted" means.
	// Two implementations of that question would eventually disagree, and the one
	// that disagreed by admitting too much would be a consent violation.
	Consent = schema.Consent
	Answer  = schema.Answer
)

// The three states of a consent answer, and the property that holds the record.
// Re-exported as values (not just types) because a caller comparing against a bare
// string literal is writing the policy a second time.
const (
	Unanswered = schema.Unanswered
	Granted    = schema.Granted
	Refused    = schema.Refused

	// PreferencesKey is the User.Properties entry the consent record nests inside.
	PreferencesKey = schema.PreferencesKey
)

// ConsentOf decodes a consent record out of a preferences blob, failing closed on
// every malformed input (see schema.ConsentOf). Exposed as a variable bound to the
// core function so there is one implementation, not a wrapper that could drift.
var ConsentOf = schema.ConsentOf

// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package model exposes the iam2 core's identity value types to external feature
// modules (hanzoiam/*) WITHOUT leaking internal/. They are ALIASES of the core
// schema, so a module and the core share ONE type — no mapping, no drift.
package model

import "github.com/hanzoai/iam/internal/schema"

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
)

// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package model exposes the iam2 core's identity value types to external feature
// modules (hanzoiam/*) WITHOUT leaking internal/. They are ALIASES of the core
// schema, so a module and the core share ONE type — no mapping, no drift.
package model

import "github.com/hanzoai/iam2/internal/schema"

type (
	User         = schema.User
	Application  = schema.Application
	Organization = schema.Organization
)

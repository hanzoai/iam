// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// origin is where a mint was asked from.
type origin struct {
	ip, method, path string
}

// originOf reads the origin off a request.
func originOf(c *zip.Ctx) origin {
	return origin{ip: httpx.ClientIP(c), method: c.Method(), path: c.Path()}
}

// issued is a SuperAdmin trail row's Object.
type issued struct {
	Sub      string   `json:"sub"`
	Client   string   `json:"client"`
	Audience []string `json:"audience,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	Kind     string   `json:"kind"`
	Jti      string   `json:"jti"`
	Expires  int64    `json:"expires"`
	Assumed  string   `json:"assumed,omitempty"`
}

// trail writes the ActionSuperAdminToken row for a SuperAdmin token.
func trail(ctx context.Context, db orm.DB, at origin) func(Claims) error {
	return func(cl Claims) error {
		home := cl.Orgs[0].Org
		m := issued{
			Sub:      cl.Subject,
			Client:   cl.Azp,
			Audience: cl.Audience,
			Scope:    cl.Scope,
			Kind:     cl.TokenType,
			Jti:      cl.ID,
			Assumed:  cl.Assumed,
		}
		if cl.ExpiresAt != nil {
			m.Expires = cl.ExpiresAt.Unix()
		}
		object, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return store.Append(ctx, db, &schema.AuditLog{
			Owner:        home,
			Organization: cl.Owner,
			User:         home + "/" + cl.Name,
			ClientIp:     at.ip,
			Method:       at.method,
			RequestUri:   at.path,
			Action:       schema.ActionSuperAdminToken,
			Object:       string(object),
			StatusCode:   200,
		})
	}
}

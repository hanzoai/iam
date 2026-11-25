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

// origin is where a mint was asked from: the verified visitor address, the
// method, and the path. An in-process mint carries a path and nothing else.
type origin struct {
	ip, method, path string
}

// originOf reads the origin off a request.
func originOf(c *zip.Ctx) origin {
	return origin{ip: httpx.ClientIP(c), method: c.Method(), path: c.Path()}
}

// issued is what a SuperAdmin token audit row records about the minted token.
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

// tokenTrail is the Signer's fail-closed audit hook for any token carrying
// SuperAdmin authority: one schema.ActionSuperAdminToken row, written before
// the token is released, filed under the admin org. The error is returned to
// the Signer so a row that cannot be persisted mints no token.
func tokenTrail(ctx context.Context, db orm.DB, at origin) func(Claims) error {
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

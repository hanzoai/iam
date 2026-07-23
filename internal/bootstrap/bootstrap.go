// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package bootstrap serves the operator-driven service-account provisioning
// endpoints — `POST /v1/iam/admin/{applications,users}/upsert`. The Hanzo K8s
// operator (operator-core) reconciles an IAM CR's spec.applications[]/users[] here,
// wiring the service-account OAuth apps that KMS/signers authenticate with, with NO
// human admin in the loop. It is idempotent (create OR update by the natural key)
// so a ~30s reconcile is a no-op once converged.
//
// Auth is a UNIFIED SERVICE TOKEN presented as `Authorization: Bearer <token>`,
// validated constant-time against the first non-empty of HANZO_API_KEY /
// KMS_SERVICE_TOKEN / IAM_SERVICE_TOKEN — the same pipeline the old iam used. The
// token is system-level (bypasses the org-membership gate), so these routes live in
// the PUBLIC group (before the Guard) and self-authenticate here. An unset token
// fails closed: no service token configured → no bootstrap.
package bootstrap

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/httpx"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// Route registers the bootstrap upsert endpoints on the PUBLIC group r (they
// self-authenticate via the service token, not a bearer principal).
func Route(r zip.Router, db orm.DB) {
	r.Post("/v1/iam/admin/applications/upsert", upsertApplication(db))
	r.Post("/v1/iam/admin/users/upsert", upsertUser(db))
}

func unauthorized(c *zip.Ctx) error {
	return c.JSON(401, map[string]any{"status": "error", "msg": "a valid service token is required"})
}

// appUpsertReq is the operator's application upsert body (operator-core UpsertRequest).
type appUpsertReq struct {
	Organization string   `json:"organization"`
	Name         string   `json:"name"`
	ClientId     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	GrantTypes   []string `json:"grantTypes"`
	RedirectUris []string `json:"redirectUris"`
	DisplayName  string   `json:"displayName"`
	Cert         string   `json:"cert"`
}

// upsertApplication idempotently creates or updates a service-account application,
// keyed by (Owner="admin", Name) — applications are platform-owned. Returns
// {status:"ok", action:"created"|"updated", data:{name, organization, clientId,
// clientSecret}} — the shape operator-core parses. A missing clientSecret preserves
// the existing one (no rotation on a steady-state reconcile) or is generated.
func upsertApplication(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		if !httpx.ServiceTokenAuth(c) {
			return unauthorized(c)
		}
		ctx := c.Context()
		var req appUpsertReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body: "+err.Error()))
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			return c.JSON(400, errResp("name is required"))
		}

		existing, err := store.GetApplicationByName(ctx, db, "admin", req.Name)
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		if req.ClientSecret == "" {
			if existing != nil && existing.ClientSecret != "" {
				req.ClientSecret = existing.ClientSecret
			} else {
				req.ClientSecret = randomSecret()
			}
		}
		if req.ClientId == "" {
			req.ClientId = req.Name // <org>-<app> convention: clientId == name
		}

		action := "created"
		if existing != nil {
			action = "updated"
			existing.ClientId = req.ClientId
			existing.ClientSecret = req.ClientSecret
			existing.Organization = pick(req.Organization, existing.Organization)
			if req.DisplayName != "" {
				existing.DisplayName = req.DisplayName
			}
			if len(req.GrantTypes) > 0 {
				existing.GrantTypes = req.GrantTypes
			}
			if len(req.RedirectUris) > 0 {
				existing.RedirectUris = req.RedirectUris
			}
			if req.Cert != "" {
				existing.Cert = req.Cert
			}
			existing.EnablePassword = true
			if err := existing.UpdateCtx(ctx); err != nil {
				return c.JSON(500, errResp("server_error"))
			}
		} else {
			a := orm.New[schema.Application](db)
			model := a.Model
			a.Owner, a.Name = "admin", req.Name
			a.ClientId, a.ClientSecret = req.ClientId, req.ClientSecret
			a.Organization, a.DisplayName = req.Organization, pick(req.DisplayName, req.Name)
			a.GrantTypes, a.RedirectUris, a.Cert = req.GrantTypes, req.RedirectUris, req.Cert
			a.EnablePassword, a.ExpireInHours = true, 1
			a.Model = model
			a.SetId("admin/" + req.Name)
			if err := a.CreateCtx(ctx); err != nil {
				return c.JSON(500, errResp("server_error"))
			}
		}
		return c.JSON(200, map[string]any{
			"status": "ok", "action": action,
			"data": map[string]any{
				"name": req.Name, "organization": req.Organization,
				"clientId": req.ClientId, "clientSecret": req.ClientSecret,
			},
		})
	}
}

// userUpsertReq is the operator's user upsert body.
type userUpsertReq struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Password     string `json:"password"`
	PasswordType string `json:"passwordType"`
	IsAdmin      bool   `json:"isAdmin"`
}

// upsertUser idempotently creates or updates a user keyed by (Owner, Name). The
// password is argon2id-hashed (SOTA; never stored plaintext); an empty password preserves
// the existing credential. Returns {status:"ok", action, data:{owner, name}}.
func upsertUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		if !httpx.ServiceTokenAuth(c) {
			return unauthorized(c)
		}
		ctx := c.Context()
		var req userUpsertReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body: "+err.Error()))
		}
		req.Owner, req.Name = strings.TrimSpace(req.Owner), strings.TrimSpace(req.Name)
		if req.Owner == "" || req.Name == "" {
			return c.JSON(400, errResp("owner and name are required"))
		}

		var hash string
		if req.Password != "" {
			h, err := cred.Hash(req.Password)
			if err != nil {
				return c.JSON(500, errResp("server_error"))
			}
			hash = h
		}

		existing, err := store.GetUserByName(ctx, db, req.Owner, req.Name)
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		action := "created"
		if existing != nil {
			action = "updated"
			existing.DisplayName = pick(req.DisplayName, existing.DisplayName)
			existing.Email = pick(req.Email, existing.Email)
			existing.Phone = pick(req.Phone, existing.Phone)
			existing.IsAdmin = req.IsAdmin
			if hash != "" {
				existing.PasswordHash, existing.PasswordType, existing.PasswordSalt = hash, cred.TypeArgon2id, ""
			}
			existing.UpdatedTime = now()
			if err := existing.UpdateCtx(ctx); err != nil {
				return c.JSON(500, errResp("server_error"))
			}
		} else {
			u := orm.New[schema.User](db)
			model := u.Model
			u.Owner, u.Name = req.Owner, req.Name
			u.DisplayName, u.Email, u.Phone, u.IsAdmin = req.DisplayName, req.Email, req.Phone, req.IsAdmin
			if hash != "" {
				u.PasswordHash, u.PasswordType = hash, cred.TypeArgon2id
			}
			u.CreatedTime, u.UpdatedTime = now(), now()
			u.Model = model
			u.SetId(req.Owner + "/" + req.Name)
			if err := u.CreateCtx(ctx); err != nil {
				return c.JSON(500, errResp("server_error"))
			}
		}
		return c.JSON(200, map[string]any{
			"status": "ok", "action": action,
			"data": map[string]any{"owner": req.Owner, "name": req.Name},
		})
	}
}

// ---- helpers ----

// decode reads the raw JSON body (content-type independent) into v.
func decode(c *zip.Ctx, v any) error {
	body := c.Body()
	if len(body) == 0 {
		return errors.New("empty request body")
	}
	return json.Unmarshal(body, v)
}

func errResp(msg string) map[string]any { return map[string]any{"status": "error", "msg": msg} }

// pick returns a if non-empty (trimmed), else b.
func pick(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// randomSecret returns a 32-byte URL-safe random client secret.
func randomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

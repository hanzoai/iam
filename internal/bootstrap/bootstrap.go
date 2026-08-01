// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package bootstrap serves the operator-driven service-account provisioning
// endpoints — `POST /v1/iam/admin/{applications,users}/upsert`. The Hanzo K8s
// operator (operator-core) reconciles an IAM CR's spec.applications[]/users[] here,
// binding the service-account OAuth apps that KMS/signers authenticate with, with NO
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

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
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
	// Public declares a client that CANNOT hold a credential — a browser SPA,
	// a CLI, a desktop app. It proves itself with PKCE instead, and the token
	// endpoint treats "no stored secret" as exactly that (token.go: a secret is
	// verified only when one is stored). Without this flag every upsert minted
	// a secret, so a public client could never be registered at all and its
	// browser code->token exchange 401'd `invalid_client` forever.
	Public bool `json:"public"`
	// IsShared declares that this application serves EVERY organization, not only
	// the one named in Organization. It is the honest description of a brand app —
	// hanzo-id, hanzo-chat, a brand console — whose customers each live in their own
	// tenant: self-service onboarding moves a founder OUT of the brand org, so
	// `user.Owner != app.Organization` is the steady state and the app really does
	// serve every org. Application.ServesOrg reads it as one of the three ways to
	// say yes.
	//
	// A POINTER because omission must PRESERVE. This upsert is the operator's
	// steady-state reconcile and most callers say nothing about sharing; a plain
	// bool would read as false on every one of them and silently un-share an app —
	// the same shape of accident that de-secreted apps through update-application.
	// Nil means "not stated, leave it"; only an explicit true or false moves it.
	IsShared *bool `json:"isShared"`
	// ExpireInHours and RefreshExpireInHours are the application's token
	// lifetimes. They are the ONLY declarative way to say that a refresh token
	// must OUTLIVE its access token: with neither stated, oidc.refreshTTL clamps
	// the refresh lifetime to the access lifetime, so the refresh_token grant the
	// registration advertises expires at the same instant as the token it was
	// meant to renew and can never be exercised. `hanzo-cli` sat in exactly that
	// state — a browser re-login every hour, and a live refresh returning 401.
	//
	// POINTERS, for the same reason as IsShared: a plain float would read as 0 on
	// every reconcile that says nothing and reset a deliberate lifetime back to
	// the default. Nil means "not stated, leave it".
	ExpireInHours        *float64 `json:"expireInHours"`
	RefreshExpireInHours *float64 `json:"refreshExpireInHours"`
}

// upsertApplication creates an application or updates it in place, so a
// deployment can declare the applications it needs and run the same declaration
// on every environment and on every redeploy.
//
// It says which of the two it did. Leave the client secret out and the existing
// one is kept — so re-running your deployment does not rotate a credential your
// running services are holding.
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
		var existingSecret string
		if existing != nil {
			existingSecret = existing.ClientSecret
		}
		req.ClientSecret = resolveSecret(req.Public, req.ClientSecret, existing != nil, existingSecret)
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
			if req.IsShared != nil {
				existing.IsShared = *req.IsShared
			}
			existing.ExpireInHours = ttl(req.ExpireInHours, existing.ExpireInHours)
			existing.RefreshExpireInHours = ttl(req.RefreshExpireInHours, existing.RefreshExpireInHours)
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
			a.EnablePassword = true
			a.ExpireInHours = ttl(req.ExpireInHours, schema.DefaultExpireInHours)
			a.RefreshExpireInHours = ttl(req.RefreshExpireInHours, 0)
			// A new app is single-tenant unless it says otherwise — fail closed.
			a.IsShared = req.IsShared != nil && *req.IsShared
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

// upsertUser creates a person or updates them in place, so a deployment can
// declare the accounts it needs and re-run that declaration safely.
//
// Passwords are hashed before they are stored. Leave the password out and their
// current one is kept, so a redeploy never locks somebody out.
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
			// A new row obeys THE username rule; an existing one is found above and
			// merely updated, so a legacy name is never rewritten by an upsert that
			// happened to touch it. This path writes through orm directly rather than
			// users.Create (it seeds the first admin, before any principal exists), so
			// it states the rule itself — the one place that has to.
			name, err := schema.Username(req.Name)
			if err != nil {
				return c.JSON(400, errResp(err.Error()))
			}
			req.Name = name // the id and the response report what was STORED
			u := orm.New[schema.User](db)
			model := u.Model
			u.Owner, u.Name = req.Owner, name
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

// resolveSecret decides the credential an upsert stores. It is the ONE place
// public-vs-confidential is settled, split out so the rule is testable without
// a store:
//
//   - public       -> NO secret. That absence is exactly what the token endpoint
//     reads as "PKCE, do not demand client auth", so it must also
//     CLEAR one left by an earlier confidential registration.
//   - explicit     -> honour it; rotation is deliberate.
//   - existing app -> preserve what it has, INCLUDING an empty secret. Minting
//     one because "the stored secret is empty" would silently
//     turn a public client confidential on the next reconcile.
//   - brand new    -> mint one.
func resolveSecret(public bool, requested string, hasExisting bool, existing string) string {
	switch {
	case public:
		return ""
	case requested != "":
		return requested
	case hasExisting:
		return existing
	default:
		return randomSecret()
	}
}

// decode reads the raw JSON body (content-type independent) into v.
func decode(c *zip.Ctx, v any) error {
	body := c.Body()
	if len(body) == 0 {
		return errors.New("empty request body")
	}
	return json.Unmarshal(body, v)
}

func errResp(msg string) map[string]any { return map[string]any{"status": "error", "msg": msg} }

// ttl applies an optionally-declared token lifetime: nil PRESERVES cur (an
// omitted field never resets a deliberate lifetime on a steady-state reconcile),
// a stated value wins — including an explicit 0, which is how a document says
// "back to the default".
func ttl(declared *float64, cur float64) float64 {
	if declared == nil {
		return cur
	}
	return *declared
}

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

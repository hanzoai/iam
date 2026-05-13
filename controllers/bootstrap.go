// Copyright 2025 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/cred"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// BootstrapApplicationUpsert
//
// Endpoint:  POST /v1/iam/admin/applications/upsert
// Auth:      service-token via Authorization: Bearer <token>
//
//	where token is one of $HANZO_API_KEY / $KMS_SERVICE_TOKEN / $IAM_SERVICE_TOKEN.
//	Validated by routers/auto_signin_filter.go before this handler runs.
//
// Idempotent operator-driven application provisioning. Used by liquid-operator
// to wire service accounts (KMS, BD treasury signer, ATS settlement key, etc.)
// into IAM with the right grant types — no human in the loop.
//
// If the app exists by (owner, name) → update grants + rotate clientSecret.
// If not → create.
//
// On 401: missing or invalid service token (handled upstream).
// On 400: malformed body or missing required fields.
//
// Body:
//
//	{
//	  "organization": "liquidity",      // required
//	  "name":         "liquidity-kms",  // required
//	  "clientId":     "kms-app",        // required
//	  "clientSecret": "...",            // optional; generated if omitted (preferred)
//	  "grantTypes":   ["client_credentials", "refresh_token"],
//	  "redirectUris": ["..."]           // optional, for non-CC flows
//	  "displayName":  "Liquidity KMS"   // optional
//	}
//
// Response on success:
//
//	{ "status": "ok", "action": "created"|"updated",
//	  "data": { "name": "...", "clientId": "...", "clientSecret": "..." } }
//
// The clientSecret in the response is the source-of-truth value the caller
// must persist (e.g. into a k8s Secret).
func (c *ApiController) BootstrapApplicationUpsert() {
	var req struct {
		Organization string   `json:"organization"`
		Name         string   `json:"name"`
		ClientId     string   `json:"clientId"`
		ClientSecret string   `json:"clientSecret"`
		GrantTypes   []string `json:"grantTypes"`
		RedirectUris []string `json:"redirectUris"`
		DisplayName  string   `json:"displayName"`
	}
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if req.Organization == "" || req.Name == "" || req.ClientId == "" {
		c.ResponseError("organization, name, and clientId are required")
		return
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"client_credentials"}
	}

	// Owner = the requested organization. The JWT `owner` claim carries
	// this value verbatim, and KMS (and any other URL-org-scoped service)
	// requires `owner == URL org segment` to authorize a request. There
	// is NO `owner=admin` shortcut — that was the cross-tenant root-key
	// bug Red demonstrated 2026-04-21. Empty Organization defaults to
	// "admin" so the bootstrap admin-app keeps working unchanged.
	owner := req.Organization
	if owner == "" {
		owner = "admin"
	}
	id := owner + "/" + req.Name

	existing, _ := object.GetApplication(id)
	// Idempotency contract: when the caller submits an empty clientSecret
	// AND the application already exists with a non-empty stored secret,
	// PRESERVE the existing secret. Without this, every operator reconcile
	// cycle (which submits "" expecting BootstrapApplicationUpsert to mean
	// "leave the secret alone if you can") silently rotates the credential
	// and breaks every consumer that read the env at pod boot. Only mint a
	// fresh secret when (a) creating a brand-new app, OR (b) caller passed
	// an explicit non-empty value (treated as a deliberate override).
	if req.ClientSecret == "" {
		if existing != nil && existing.ClientSecret != "" {
			req.ClientSecret = existing.ClientSecret
		} else {
			req.ClientSecret = generateBootstrapSecret()
		}
	}
	if existing != nil {
		existing.ClientId = req.ClientId
		existing.ClientSecret = req.ClientSecret
		existing.GrantTypes = req.GrantTypes
		if len(req.RedirectUris) > 0 {
			existing.RedirectUris = req.RedirectUris
		}
		if req.DisplayName != "" {
			existing.DisplayName = req.DisplayName
		}
		// Bootstrap is system-level — bypass org-membership gate.
		ok, err := object.UpdateApplication(id, existing, true, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.Data["json"] = map[string]any{
			"status": "ok",
			"action": "updated",
			"data": map[string]string{
				"name":         req.Name,
				"organization": req.Organization,
				"clientId":     req.ClientId,
				"clientSecret": req.ClientSecret,
			},
			"updated": ok,
		}
		c.ServeJSON()
		return
	}

	// Bootstrap is operator-driven — the moment we seed an app it should
	// be usable for browser login. Auto-create the org row if it's the
	// first app in that tenant, then enable password+signup so the very
	// next /login call against this app succeeds without a follow-up
	// admin tweak. Operator already holds the service token; trust it.
	if err := ensureOrganization(req.Organization); err != nil {
		c.ResponseError(err.Error())
		return
	}
	app := &object.Application{
		Owner:          owner,
		Name:           req.Name,
		Organization:   req.Organization,
		DisplayName:    req.DisplayName,
		ClientId:       req.ClientId,
		ClientSecret:   req.ClientSecret,
		GrantTypes:     req.GrantTypes,
		RedirectUris:   req.RedirectUris,
		ExpireInHours:  24,
		TokenFormat:    "JWT",
		EnablePassword: true,
		EnableSignUp:   true,
		// Sign JWTs with the admin-seeded cert by default. init.go puts
		// the IAM cert (RSA keypair) in the admin namespace; every tenant
		// app can reference it to mint tokens. Per-tenant certs are an
		// explicit override (set req.Cert / future field).
		Cert: object.AdminCertName(),
	}
	if app.DisplayName == "" {
		app.DisplayName = req.Name
	}

	created, err := object.AddApplication(app)
	if err != nil {
		// xorm's per-org engine routing is asymmetric on the read/write sides
		// for some org configurations: getApplication can return nil while
		// AddApplication's INSERT lands in the global engine, where the row
		// already exists from a prior call (or from the LiquidIAM tenant seed
		// in init_data.json). When that happens the underlying SQLite raises
		// UNIQUE on (owner, name). Treat it as "the row exists" and fall
		// through to UpdateApplication so the operator's repeated upserts
		// are actually idempotent.
		if isUniqueConstraintErr(err) {
			ok, uerr := object.UpdateApplication(id, app, true, c.GetAcceptLanguage())
			if uerr != nil {
				c.ResponseError(uerr.Error())
				return
			}
			c.Data["json"] = map[string]any{
				"status": "ok",
				"action": "updated",
				"data": map[string]string{
					"name":         req.Name,
					"organization": req.Organization,
					"clientId":     req.ClientId,
					"clientSecret": req.ClientSecret,
				},
				"updated": ok,
			}
			c.ServeJSON()
			return
		}
		c.ResponseError(err.Error())
		return
	}
	c.Data["json"] = map[string]any{
		"status": "ok",
		"action": "created",
		"data": map[string]string{
			"name":         req.Name,
			"organization": req.Organization,
			"clientId":     req.ClientId,
			"clientSecret": req.ClientSecret,
		},
		"created": created,
	}
	c.ServeJSON()
}

// BootstrapUserUpsert
//
// Endpoint:  POST /v1/iam/admin/users/upsert
// Auth:      service-token via Authorization: Bearer <token>
//
//	where token is one of $HANZO_API_KEY / $KMS_SERVICE_TOKEN / $IAM_SERVICE_TOKEN.
//	Validated by routers/auto_signin_filter.go before this handler runs.
//
// Idempotent operator-driven user provisioning. Used by liquid-operator to
// reconcile LiquidIAM.spec.users[] against IAM — no human admin in the loop.
//
// If the user exists by (owner, name) → update; else insert. Passwords are
// always hashed at rest (argon2id by default; bcrypt rejected; "plain" passes
// through only when explicitly requested for sandbox fixtures).
//
// Body:
//
//	{
//	  "owner":             "example-org",      // required
//	  "name":              "z",                // required
//	  "displayName":       "Z",
//	  "email":             "z@example.org",
//	  "phone":             "5550001234",
//	  "countryCode":       "US",
//	  "password":          "...",
//	  "passwordType":      "argon2id"|"plain", // default argon2id; bcrypt rejected
//	  "type":              "normal-user",      // default normal-user
//	  "isAdmin":           false,
//	  "signupApplication": "example-app",
//	  "emailVerified":     true,
//	  "properties":        { "...": "..." }    // future-proof free-form
//	}
//
// Response on success:
//
//	{ "status": "ok", "data": { "created": bool, "name": "...", "email": "..." } }
func (c *ApiController) BootstrapUserUpsert() {
	var req struct {
		Owner             string            `json:"owner"`
		Name              string            `json:"name"`
		DisplayName       string            `json:"displayName"`
		Email             string            `json:"email"`
		Phone             string            `json:"phone"`
		CountryCode       string            `json:"countryCode"`
		Password          string            `json:"password"`
		PasswordType      string            `json:"passwordType"`
		Type              string            `json:"type"`
		IsAdmin           bool              `json:"isAdmin"`
		SignupApplication string            `json:"signupApplication"`
		EmailVerified     bool              `json:"emailVerified"`
		Properties        map[string]string `json:"properties"`
	}
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.ResponseError(err.Error())
		return
	}

	req.Owner = strings.TrimSpace(req.Owner)
	req.Name = strings.TrimSpace(req.Name)
	if req.Owner == "" || req.Name == "" {
		c.ResponseError("owner and name are required")
		return
	}

	if err := ensureOrganization(req.Owner); err != nil {
		c.ResponseError(err.Error())
		return
	}

	if req.Type == "" {
		req.Type = "normal-user"
	}

	if req.Email != "" && !util.IsEmailValid(req.Email) {
		c.ResponseError(fmt.Sprintf("invalid email: %s", req.Email))
		return
	}

	if req.Phone != "" && os.Getenv("SANDBOX_SKIP_PHONE_VALIDATION") == "" {
		// E.164 acceptable shape: + followed by digits, or libphonenumber-valid.
		if !util.IsPhoneValid(req.Phone, req.CountryCode) {
			c.ResponseError(fmt.Sprintf("invalid phone: %s (countryCode=%s)", req.Phone, req.CountryCode))
			return
		}
	}

	hashedPassword, hashedSalt, hashedType, err := hashBootstrapPassword(req.Password, req.PasswordType)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	id := req.Owner + "/" + req.Name
	existing, _ := object.GetUser(id)

	if existing != nil {
		existing.DisplayName = pickNonEmpty(req.DisplayName, existing.DisplayName)
		existing.Email = pickNonEmpty(req.Email, existing.Email)
		existing.Phone = pickNonEmpty(req.Phone, existing.Phone)
		existing.CountryCode = pickNonEmpty(req.CountryCode, existing.CountryCode)
		existing.Type = pickNonEmpty(req.Type, existing.Type)
		existing.SignupApplication = pickNonEmpty(req.SignupApplication, existing.SignupApplication)
		existing.IsAdmin = req.IsAdmin
		existing.EmailVerified = req.EmailVerified
		if req.Properties != nil {
			if existing.Properties == nil {
				existing.Properties = map[string]string{}
			}
			for k, v := range req.Properties {
				existing.Properties[k] = v
			}
		}
		if hashedPassword != "" {
			existing.Password = hashedPassword
			existing.PasswordSalt = hashedSalt
			existing.PasswordType = hashedType
		}

		// Persist verbatim — UpdateUserForAllFields does AllCols().Update so
		// the password, salt, and type we computed land exactly as-is. This
		// also handles the displayName/email/phone/etc updates without the
		// column allowlist gymnastics UpdateUser requires.
		ok, uerr := object.UpdateUserForAllFields(id, existing)
		if uerr != nil {
			c.ResponseError(uerr.Error())
			return
		}
		c.Data["json"] = map[string]any{
			"status": "ok",
			"data": map[string]any{
				"created": false,
				"name":    req.Name,
				"email":   existing.Email,
			},
			"updated": ok,
		}
		c.ServeJSON()
		return
	}

	user := &object.User{
		Owner:             req.Owner,
		Name:              req.Name,
		DisplayName:       req.DisplayName,
		Email:             req.Email,
		Phone:             req.Phone,
		CountryCode:       req.CountryCode,
		Type:              req.Type,
		IsAdmin:           req.IsAdmin,
		SignupApplication: req.SignupApplication,
		EmailVerified:     req.EmailVerified,
		Properties:        req.Properties,
		Password:          hashedPassword,
		PasswordSalt:      hashedSalt,
		PasswordType:      hashedType,
	}
	if user.DisplayName == "" {
		user.DisplayName = req.Name
	}

	created, err := object.AddUser(user, c.GetAcceptLanguage())
	if err != nil {
		// Mirror the applications/upsert race-tolerance: if the global engine
		// holds a row that the per-org getUser missed, AddUser's INSERT raises
		// UNIQUE. Fall through to update so repeated operator calls are
		// genuinely idempotent.
		if isUniqueConstraintErr(err) {
			ok, uerr := object.UpdateUserForAllFields(id, user)
			if uerr != nil {
				c.ResponseError(uerr.Error())
				return
			}
			c.Data["json"] = map[string]any{
				"status": "ok",
				"data": map[string]any{
					"created": false,
					"name":    req.Name,
					"email":   user.Email,
				},
				"updated": ok,
			}
			c.ServeJSON()
			return
		}
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = map[string]any{
		"status": "ok",
		"data": map[string]any{
			"created": created,
			"name":    req.Name,
			"email":   user.Email,
		},
	}
	c.ServeJSON()
}

// hashBootstrapPassword normalizes the requested passwordType and returns the
// (password, salt, passwordType) triple the controller will pass downstream.
//
//	""           → "argon2id"  (default — argon2id hash with random salt)
//	"argon2id"   → "argon2id"  (hash with random salt)
//	"plain"      → "plain"     (sandbox/test fixture; plaintext returned)
//	"bcrypt"     → error       (deprecated, use argon2id)
//	other        → error       (unsupported)
//
// An empty password is allowed (e.g. OAuth-only users) and returns ("","","").
//
// Note: when the caller writes a "plain" row through AddUser (new user),
// IAM's existing security gate auto-upgrades plain → argon2id at insert time
// (see object.User.UpdateUserPassword + object.sanitizeOrgPasswordType).
// That means in practice "plain" is the controller-boundary contract for
// "send me plaintext and I'll hash it for you" — at-rest the row is always
// argon2id. Existing rows updated through UpdateUserForAllFields persist the
// fields verbatim; "plain" at rest there is reserved for explicit fixture
// scenarios under SANDBOX_* gates and must not be used in production.
func hashBootstrapPassword(password, passwordType string) (string, string, string, error) {
	if password == "" {
		return "", "", "", nil
	}
	switch passwordType {
	case "", "argon2id":
		cm := cred.GetCredManager("argon2id")
		if cm == nil {
			return "", "", "", fmt.Errorf("argon2id cred manager unavailable")
		}
		salt := util.GeneratePasswordSalt()
		hashed := cm.GetHashedPassword(password, salt)
		if hashed == "" {
			return "", "", "", fmt.Errorf("argon2id hash failed")
		}
		return hashed, salt, "argon2id", nil
	case "plain":
		return password, "", "plain", nil
	case "bcrypt":
		return "", "", "", fmt.Errorf("passwordType 'bcrypt' is rejected — use 'argon2id'")
	default:
		return "", "", "", fmt.Errorf("unsupported passwordType: %s", passwordType)
	}
}

func pickNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// SQLite: "UNIQUE constraint failed: application.owner, application.name (1555)"
	// Postgres: "duplicate key value violates unique constraint"
	// MySQL:    "Error 1062: Duplicate entry"
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "Duplicate entry")
}

// generateBootstrapSecret returns a 32-byte URL-safe random secret.
func generateBootstrapSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// ensureOrganization creates the org row if it doesn't exist. Bootstrap is
// trusted (operator-driven), and password-login on a freshly-seeded app
// requires the org row exist. Idempotent: existing orgs are left alone.
//
// Empty name resolves to the configured admin org so the legacy unset-org
// callers (which fell through to "admin" elsewhere) keep working.
func ensureOrganization(name string) error {
	if name == "" {
		name = conf.AdminOrg
	}
	id := util.GetId(conf.AdminOrg, name)
	existing, err := object.GetOrganization(id)
	if err != nil {
		return fmt.Errorf("lookup org %s: %w", id, err)
	}
	if existing != nil {
		return nil
	}
	org := &object.Organization{
		Owner:        conf.AdminOrg,
		Name:         name,
		DisplayName:  name,
		PasswordType: "argon2id",
		AccountItems: []*object.AccountItem{
			{Name: "Organization", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
			{Name: "ID", Visible: true, ViewRule: "Public", ModifyRule: "Immutable"},
			{Name: "Name", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
			{Name: "Display name", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
			{Name: "Email", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
			{Name: "Phone", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
			{Name: "Password", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		},
	}
	if _, err := object.AddOrganization(org); err != nil {
		return fmt.Errorf("create org %s: %w", id, err)
	}
	return nil
}

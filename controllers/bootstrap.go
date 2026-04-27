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

	"github.com/hanzoai/iam/object"
)

// BootstrapApplicationUpsert
//
// Endpoint:  POST /v1/iam/admin/applications/upsert
// Auth:      service-token via Authorization: Bearer <token>
//            where token is one of $HANZO_API_KEY / $KMS_SERVICE_TOKEN / $IAM_SERVICE_TOKEN.
//            Validated by routers/auto_signin_filter.go before this handler runs.
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
	if req.ClientSecret == "" {
		req.ClientSecret = generateBootstrapSecret()
	}

	// Owner. Apps used by system services live under owner='admin' so they
	// aren't bound to a single tenant. A per-tenant caller can set owner via
	// the organization name explicitly when that's intentional.
	owner := "admin"
	if req.Organization != "" && req.Organization != "liquidity" && req.Organization != "admin" {
		owner = req.Organization
	}
	id := owner + "/" + req.Name

	existing, _ := object.GetApplication(id)
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
		EnablePassword: false,
		EnableSignUp:   false,
	}
	if app.DisplayName == "" {
		app.DisplayName = req.Name
	}

	created, err := object.AddApplication(app)
	if err != nil {
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

// generateBootstrapSecret returns a 32-byte URL-safe random secret.
func generateBootstrapSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

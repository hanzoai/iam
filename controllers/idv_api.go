// Copyright 2025 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/hanzoai/iam/idv"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"

	cidv "github.com/hanzoai/idv/provider"
)

// IDVService is the global IDV service instance. Initialized via InitIDV().
var IDVService *idv.Service

// IDVHandler is the global IDV HTTP handler.
var IDVHandler *idv.Handler

// InitIDV initializes the IDV service with provider configs from environment.
func InitIDV(amlURL, jumioToken, jumioSecret, jumioEndpoint,
	onfidoToken, onfidoWebhookToken, onfidoEndpoint,
	plaidClientID, plaidSecret, plaidEndpoint,
	webhookSecret, bdWebhookURL string) {

	IDVService = idv.NewService(amlURL)

	if jumioToken != "" {
		p := cidv.NewJumio(cidv.JumioConfig{
			BaseURL:   jumioEndpoint,
			APIToken:  jumioToken,
			APISecret: jumioSecret,
		})
		IDVService.RegisterProvider(cidv.ProviderJumio, p)
	}

	if onfidoToken != "" {
		p := cidv.NewOnfido(cidv.OnfidoConfig{
			BaseURL:      onfidoEndpoint,
			APIToken:     onfidoToken,
			WebhookToken: onfidoWebhookToken,
		})
		IDVService.RegisterProvider(cidv.ProviderOnfido, p)
	}

	if plaidClientID != "" {
		p := cidv.NewPlaid(cidv.PlaidConfig{
			BaseURL:  plaidEndpoint,
			ClientID: plaidClientID,
			Secret:   plaidSecret,
		})
		IDVService.RegisterProvider(cidv.ProviderPlaid, p)
	}

	IDVHandler = &idv.Handler{
		Svc:           IDVService,
		WebhookSecret: webhookSecret,
		BDWebhookURL:  bdWebhookURL,
	}
}

// VerifyIdentity initiates an IDV verification flow.
// @Title VerifyIdentity
// @Tag IDV API
// @Description Initiate identity verification (IDV + sanctions + PEP)
// @Param   body  body   idv.VerifyIdentityRequest  true  "Verification request"
// @Success 200 {object} idv.VerifyIdentityResponse
// @router /verify-identity [post]
func (c *ApiController) VerifyIdentity() {
	if IDVService == nil {
		c.ResponseError("IDV service not configured")
		return
	}

	_, ok := c.RequireSignedIn()
	if !ok {
		return
	}

	var req idv.VerifyIdentityRequest
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.ResponseError("Invalid request body")
		return
	}
	if req.UserID == "" {
		c.ResponseError("user_id is required")
		return
	}
	if req.Provider == "" {
		req.Provider = cidv.ProviderJumio
	}

	// Resolve user to populate fields if not provided.
	user, err := object.GetUser(req.UserID)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(fmt.Sprintf("user %q not found", req.UserID))
		return
	}

	if req.GivenName == "" {
		req.GivenName = user.FirstName
	}
	if req.FamilyName == "" {
		req.FamilyName = user.LastName
	}
	if req.Email == "" {
		req.Email = user.Email
	}

	orgID := c.Ctx.Request.Header.Get("X-Org-Id")
	if orgID == "" {
		orgID = user.Owner
	}

	result, err := IDVService.Verify(c.Ctx.Request.Context(), req.UserID, orgID, req.Provider, &cidv.VerificationRequest{
		ApplicationID: req.UserID,
		GivenName:     req.GivenName,
		FamilyName:    req.FamilyName,
		DateOfBirth:   req.DateOfBirth,
		Email:         req.Email,
		Country:       req.Country,
		Workflow:      req.Workflow,
	})
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(result)
}

// VerifyIdentityWebhook processes IDV provider callbacks.
// @Title VerifyIdentityWebhook
// @Tag IDV API
// @Description Receive IDV provider webhook callback
// @Success 200 {object} controllers.Response
// @router /verify-identity/webhook [post]
func (c *ApiController) VerifyIdentityWebhook() {
	if IDVHandler == nil {
		c.ResponseError("IDV service not configured")
		return
	}
	// Delegate to the raw HTTP handler — it handles signature verification
	// and webhook parsing internally.
	IDVHandler.HandleWebhook(c.Ctx.ResponseWriter, c.Ctx.Request)
}

// GetVerifyIdentityStatus retrieves the current status of a verification.
// @Title GetVerifyIdentityStatus
// @Tag IDV API
// @Description Get identity verification status
// @Param   id    query  string  true  "Verification ID"
// @Param   provider query string false "Provider name (default: jumio)"
// @Success 200 {object} cidv.VerificationStatusResult
// @router /verify-identity/status [get]
func (c *ApiController) GetVerifyIdentityStatus() {
	if IDVService == nil {
		c.ResponseError("IDV service not configured")
		return
	}

	_, ok := c.RequireSignedIn()
	if !ok {
		return
	}

	verificationID := c.Ctx.Input.Query("id")
	if verificationID == "" {
		c.ResponseError("verification id is required")
		return
	}

	provider := c.Ctx.Input.Query("provider")
	if provider == "" {
		provider = cidv.ProviderJumio
	}

	result, err := IDVService.CheckStatus(c.Ctx.Request.Context(), provider, verificationID)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(result)
}

// VerifyAccreditation checks accredited investor status.
// @Title VerifyAccreditation
// @Tag IDV API
// @Description Verify accredited investor status
// @Param   body  body   idv.AccreditationRequest  true  "Accreditation request"
// @Success 200 {object} idv.AccreditationResult
// @router /verify-accreditation [post]
func (c *ApiController) VerifyAccreditation() {
	if IDVService == nil {
		c.ResponseError("IDV service not configured")
		return
	}

	_, ok := c.RequireSignedIn()
	if !ok {
		return
	}

	var req idv.AccreditationRequest
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.ResponseError("Invalid request body")
		return
	}
	if req.UserID == "" {
		c.ResponseError("user_id is required")
		return
	}
	if req.Method == "" {
		c.ResponseError("method is required")
		return
	}

	// Only admin or self can check accreditation.
	loggedInUser := c.GetSessionUsername()
	if loggedInUser != req.UserID && !c.IsAdmin() {
		// Allow if the logged-in user owns the user record.
		owner, name, err := util.GetOwnerAndNameFromIdWithError(req.UserID)
		if err != nil {
			c.ResponseError("Unauthorized")
			return
		}
		user, err := object.GetUser(util.GetId(owner, name))
		if err != nil || user == nil || !c.IsAdminOrSelf(user) {
			c.ResponseError("Unauthorized: only admin or self can verify accreditation")
			return
		}
	}

	result, err := IDVService.VerifyAccreditation(req.UserID, req.Method, &req)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(result)
}

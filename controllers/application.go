// Copyright 2025 Hanzo AI, Inc.
// Portions Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"strings"

	"github.com/hanzoai/beego/v2/core/utils/pagination"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// GetApplications
// @Title GetApplications
// @Tag Application API
// @Description get all applications
// @Param   owner     query    string  true        "The owner of applications."
// @Success 200 {array} object.Application The Response object
// @router /get-applications [get]
func (c *ApiController) GetApplications() {
	userId := c.GetSessionUsername()
	owner := c.Ctx.Input.Query("owner")

	// V5: only a GLOBAL admin may enumerate the admin (superuser) org's
	// applications — owner==AdminOrg is the "list every tenant's app" query (all
	// apps are stored under owner==admin). Non-global callers are hard-denied
	// here (same guard get-users uses), covering BOTH the list and the paginated
	// branch. Safe: the SPA app-list uses get-organization-applications for
	// non-default orgs (isDefaultOrganizationSelected is false for a non-global
	// admin), so no non-global console path depends on this; a non-global admin
	// reads its OWN org's apps via get-organization-applications (org-scoped).
	if owner == conf.AdminOrg && !c.IsGlobalAdmin() {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")
	organization := c.Ctx.Input.Query("organization")
	var err error

	// V5 (cross-tenant disclosure): applications are stored under
	// owner==AdminOrg with an `organization` field naming the tenant, so
	// get-applications?owner=admin would otherwise enumerate EVERY tenant's
	// apps — including the per-user app-<email> seeds (customer email
	// enumeration). A non-global admin is scoped to its OWN organization's
	// applications (+ is_shared platform apps), regardless of the caller-
	// supplied owner/organization/pageSize. Fail closed when the caller's org
	// can't be resolved (app/M2M principal, no User row) — an empty scope
	// yields only shared apps. Mirrors GetOrganizations' isGlobalAdmin/
	// callerOwner scoping: one pattern, applied consistently.
	if !c.IsGlobalAdmin() {
		callerOwner := ""
		if cu := c.getCurrentUser(); cu != nil {
			callerOwner = cu.Owner
		}
		applications, err := object.GetOrganizationApplications(owner, callerOwner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(object.GetMaskedApplications(applications, userId))
		return
	}

	if limit == "" || page == "" {
		var applications []*object.Application
		if organization == "" {
			applications, err = object.GetApplications(owner)
		} else {
			applications, err = object.GetOrganizationApplications(owner, organization)
		}
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(object.GetMaskedApplications(applications, userId))
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetApplicationCount(owner, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
		application, err := object.GetPaginationApplications(owner, paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		applications := object.GetMaskedApplications(application, userId)
		c.ResponseOk(applications, paginator.Nums())
	}
}

// GetApplication
// @Title GetApplication
// @Tag Application API
// @Description get the detail of an application
// @Param   id     query    string  true        "The id ( owner/name ) of the application."
// @Success 200 {object} object.Application The Response object
// @router /get-application [get]
func (c *ApiController) GetApplication() {
	userId := c.GetSessionUsername()
	id := c.Ctx.Input.Query("id")

	application, err := object.GetApplication(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Always populate CertPublicKey when an app references a cert.
	// The historical `?withKey=` gate broke casdoorsdk-style consumers
	// (cloud-api/Casibase, hanzo/console, hanzo/team, etc.) which
	// don't pass the param and ended up with empty certPublicKey, making
	// JWT signature verification fail with "Key must be a PEM encoded
	// PKCS1 or PKCS8 key". The cert PUBLIC key is not a secret —
	// returning it on every get-application response is correct.
	if application != nil && application.Cert != "" {
		cert, err := object.GetCert(util.GetId(application.Owner, application.Cert))
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if cert == nil {
			cert, err = object.GetCert(util.GetId(application.Organization, application.Cert))
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		}

		if cert != nil {
			application.CertPublicKey = cert.Certificate
		}
	}

	clientIp := util.GetClientIpFromRequest(c.Ctx.Request)
	object.CheckEntryIp(clientIp, nil, application, nil, c.GetAcceptLanguage())

	c.ResponseOk(object.GetMaskedApplication(application, userId))
}

// GetUserApplication
// @Title GetUserApplication
// @Tag Application API
// @Description get the detail of the user's application
// @Param   id     query    string  true        "The id ( owner/name ) of the user"
// @Success 200 {object} object.Application The Response object
// @router /get-user-application [get]
func (c *ApiController) GetUserApplication() {
	userId := c.GetSessionUsername()
	id := c.Ctx.Input.Query("id")

	user, err := object.GetUser(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), id))
		return
	}

	application, err := object.GetApplicationByUser(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The organization: %s should have one application at least"), user.Owner))
		return
	}

	c.ResponseOk(object.GetMaskedApplication(application, userId))
}

// GetOrganizationApplications
// @Title GetOrganizationApplications
// @Tag Application API
// @Description get the detail of the organization's application
// @Param   organization     query    string  true        "The organization name"
// @Success 200 {array} object.Application The Response object
// @router /get-organization-applications [get]
func (c *ApiController) GetOrganizationApplications() {
	userId := c.GetSessionUsername()
	organization := c.Ctx.Input.Query("organization")
	owner := c.Ctx.Input.Query("owner")
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if organization == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": organization")
		return
	}

	// V5/N2 (cross-tenant disclosure): a non-global admin may list applications
	// ONLY within its OWN organization. Applications are stored under
	// owner==AdminOrg with an `organization` field; without this a non-global
	// admin could pass organization=admin (or organization=<any tenant>) and
	// GetAllowedApplications' user.IsAdmin branch would return that org's apps
	// — incl the per-user app-<email> seeds (cross-tenant email enumeration).
	// Pin the org to the caller's own; global admins are unrestricted.
	if !c.IsGlobalAdmin() {
		callerOwner := ""
		if cu := c.getCurrentUser(); cu != nil {
			callerOwner = cu.Owner
		}
		if organization != callerOwner {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return
		}
	}

	if limit == "" || page == "" {
		applications, err := object.GetOrganizationApplications(owner, organization)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		applications, err = object.GetAllowedApplications(applications, userId, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(object.GetMaskedApplications(applications, userId))
	} else {
		limit := util.ParseInt(limit)

		count, err := object.GetOrganizationApplicationCount(owner, organization, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
		applications, err := object.GetPaginationOrganizationApplications(owner, organization, paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		applications, err = object.GetAllowedApplications(applications, userId, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		applications = object.GetMaskedApplications(applications, userId)
		c.ResponseOk(applications, paginator.Nums())
	}
}

// UpdateApplication
// @Title UpdateApplication
// @Tag Application API
// @Description update an application
// @Param   id     query    string  true        "The id ( owner/name ) of the application"
// @Param   body    body   object.Application  true        "The details of the application"
// @Success 200 {object} controllers.Response The Response object
// @router /update-application [post]
func (c *ApiController) UpdateApplication() {
	// An app/<name> credential may mutate OAuth clients (incl. rotating
	// another app's clientSecret — the escalation path into the capability
	// allowlists) ONLY if allowlisted for the application-admin capability
	// (fail-secure). Humans (org admins via console) are unaffected.
	if !c.requireAppCapability(object.CapAppAdmin) {
		return
	}

	id := c.Ctx.Input.Query("id")

	var application object.Application
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &application)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// V5/Red#5 (defense in depth): a non-global caller must never rename an app
	// TO a capability-reserved name (that identity belongs to the admin-owned
	// platform app). Mirrors the AddApplication guard.
	if !c.IsGlobalAdmin() && object.AppNameIsCapabilityReserved(application.Name) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	// V5/Red#6/#7: the PERSISTED app must be mutable by the caller (platform/
	// capability-reserved apps require global admin regardless of Organization;
	// otherwise org-admin of the app's own org) AND the requested result must
	// stay in the caller's own org (never touch or move another org's app, and
	// never rename INTO a reserved platform identity).
	if existing, e := object.GetApplication(id); e == nil && existing != nil {
		if !c.appMutationAllowed(existing) || !c.appMutationAllowed(&application) {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return
		}
	}

	if err = object.CheckIpWhitelist(application.IpWhitelist, c.GetAcceptLanguage()); err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateApplication(id, &application, c.IsGlobalAdmin(), c.GetAcceptLanguage()))
	c.ServeJSON()
}

// AddApplication
// @Title AddApplication
// @Tag Application API
// @Description add an application
// @Param   body    body   object.Application  true        "The details of the application"
// @Success 200 {object} controllers.Response The Response object
// @router /add-application [post]
func (c *ApiController) AddApplication() {
	if !c.requireAppCapability(object.CapAppAdmin) {
		return
	}

	var application object.Application
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &application)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// V5/Red#5 (defense in depth): a capability-allowlisted app Name is reserved
	// for the admin-owned platform app. A non-global caller must never create an
	// application with such a Name — this removes the reliance on the implicit
	// (admin,<name>) PK-collision (which only holds while the platform app is
	// seeded) and permanently forecloses the owner=admin injection into the
	// capability allowlists. Global admins (who seed/manage platform apps) pass.
	if !c.IsGlobalAdmin() && object.AppNameIsCapabilityReserved(application.Name) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	// V5/Red#6/#7: a non-global caller may create an app ONLY as an admin of its
	// own org, may not create a capability-reserved platform app, and may not
	// inject into the admin namespace (Owner==AdminOrg with a non-<org>-prefixed
	// name — validateAppName skips the prefix rule for Owner==admin).
	if !c.appMutationAllowed(&application) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}
	if !c.IsGlobalAdmin() && application.Owner == conf.AdminOrg {
		cu := c.getCurrentUser()
		if cu == nil || !strings.HasPrefix(application.Name, cu.Owner+"-") {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return
		}
	}

	count, err := object.GetApplicationCount("", "", "")
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err := checkQuotaForApplication(int(count)); err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err = object.CheckIpWhitelist(application.IpWhitelist, c.GetAcceptLanguage()); err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddApplication(&application))
	c.ServeJSON()
}

// DeleteApplication
// @Title DeleteApplication
// @Tag Application API
// @Description delete an application
// @Param   body    body   object.Application  true        "The details of the application"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-application [post]
func (c *ApiController) DeleteApplication() {
	if !c.requireAppCapability(object.CapAppAdmin) {
		return
	}

	var application object.Application
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &application)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// V5/Red#6/#7 (auth DoS): resolve the app by its REAL identity and scope the
	// delete on the PERSISTED row — a capability-reserved platform app (e.g. the
	// seeded admin/hanzo-console login app, whose loss breaks platform-wide auth)
	// requires a global admin regardless of its Organization; any other app
	// requires org-admin of the app's own org. The body's org is
	// attacker-controlled, so we never trust it.
	if existing, e := object.GetApplication(application.GetId()); e == nil && existing != nil && !c.appMutationAllowed(existing) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteApplication(&application, c.IsGlobalAdmin()))
	c.ServeJSON()
}

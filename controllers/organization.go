// Copyright 2021 The Hanzo Authors. All Rights Reserved.
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

	"github.com/hanzoai/beego/v2/core/utils/pagination"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// GetOrganizations ...
// @Title GetOrganizations
// @Tag Organization API
// @Description get organizations
// @Param   owner     query    string  true        "owner"
// @Success 200 {array} object.Organization The Response object
// @router /get-organizations [get]
func (c *ApiController) GetOrganizations() {
	owner := c.Ctx.Input.Query("owner")
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")
	organizationName := c.Ctx.Input.Query("organizationName")

	isGlobalAdmin := c.IsGlobalAdmin()
	// Non-global-admin callers are scoped to their own org. An app/<name>
	// principal (Red R-1: no longer a global admin) has no User row, so resolve
	// the scope nil-safely instead of dereferencing a nil getCurrentUser() — an
	// empty scope matches no organization (GetOrganizations returns []), which is
	// the correct least-privilege answer for a confidential client.
	callerOwner := ""
	if cu := c.getCurrentUser(); cu != nil {
		callerOwner = cu.Owner
	}
	if limit == "" || page == "" {
		var organizations []*object.Organization
		var err error
		if isGlobalAdmin {
			organizations, err = object.GetMaskedOrganizations(object.GetOrganizations(owner))
		} else {
			organizations, err = object.GetMaskedOrganizations(object.GetOrganizations(owner, callerOwner))
		}

		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(organizations)
	} else {
		if !isGlobalAdmin {
			organizations, err := object.GetMaskedOrganizations(object.GetOrganizations(owner, callerOwner))
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			c.ResponseOk(organizations)
		} else {
			limit := util.ParseInt(limit)
			count, err := object.GetOrganizationCount(owner, organizationName, field, value)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
			organizations, err := object.GetMaskedOrganizations(object.GetPaginationOrganizations(owner, organizationName, paginator.Offset(), limit, field, value, sortField, sortOrder))
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			c.ResponseOk(organizations, paginator.Nums())
		}
	}
}

// GetOrganization ...
// @Title GetOrganization
// @Tag Organization API
// @Description get organization
// @Param   id     query    string  true        "organization id"
// @Success 200 {object} object.Organization The Response object
// @router /get-organization [get]
func (c *ApiController) GetOrganization() {
	id := c.Ctx.Input.Query("id")
	organization, err := object.GetMaskedOrganization(object.GetOrganization(id))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if organization != nil && organization.MfaRememberInHours == 0 {
		organization.MfaRememberInHours = 12
	}

	c.ResponseOk(organization)
}

// UpdateOrganization ...
// @Title UpdateOrganization
// @Tag Organization API
// @Description update organization
// @Param   id     query    string  true        "The id ( owner/name ) of the organization"
// @Param   body    body   object.Organization  true        "The details of the organization"
// @Success 200 {object} controllers.Response The Response object
// @router /update-organization [post]
func (c *ApiController) UpdateOrganization() {
	// An app/<name> credential may mutate organizations only if allowlisted
	// (IAM_ORG_ADMIN_APPS = the brand consoles, which create orgs during
	// onboarding). Humans (org admins / real global admins) are unaffected.
	if !c.requireAppCapability(object.CapOrgAdmin) {
		return
	}

	id := c.Ctx.Input.Query("id")

	var organization object.Organization
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &organization)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err = object.CheckIpWhitelist(organization.IpWhitelist, c.GetAcceptLanguage()); err != nil {
		c.ResponseError(err.Error())
		return
	}

	isGlobalAdmin, _ := c.isGlobalAdmin()

	if organization.BalanceCurrency == "" {
		organization.BalanceCurrency = "USD"
	}

	c.Data["json"] = wrapActionResponse(object.UpdateOrganization(id, &organization, isGlobalAdmin))
	c.ServeJSON()
}

// AddOrganization ...
// @Title AddOrganization
// @Tag Organization API
// @Description add organization
// @Param   body    body   object.Organization  true        "The details of the organization"
// @Success 200 {object} controllers.Response The Response object
// @router /add-organization [post]
func (c *ApiController) AddOrganization() {
	if !c.requireAppCapability(object.CapOrgAdmin) {
		return
	}

	var organization object.Organization
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &organization)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	count, err := object.GetOrganizationCount("", "", "", "")
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err = checkQuotaForOrganization(int(count)); err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err = object.CheckIpWhitelist(organization.IpWhitelist, c.GetAcceptLanguage()); err != nil {
		c.ResponseError(err.Error())
		return
	}

	if organization.BalanceCurrency == "" {
		organization.BalanceCurrency = "USD"
	}

	c.Data["json"] = wrapActionResponse(object.AddOrganization(&organization))
	c.ServeJSON()
}

// DeleteOrganization ...
// @Title DeleteOrganization
// @Tag Organization API
// @Description delete organization
// @Param   body    body   object.Organization  true        "The details of the organization"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-organization [post]
func (c *ApiController) DeleteOrganization() {
	if !c.requireAppCapability(object.CapOrgAdmin) {
		return
	}

	var organization object.Organization
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &organization)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteOrganization(&organization))
	c.ServeJSON()
}

// GetDefaultApplication ...
// @Title GetDefaultApplication
// @Tag Organization API
// @Description get default application
// @Param   id     query    string  true        "organization id"
// @Success 200 {object} controllers.Response The Response object
// @router /get-default-application [get]
func (c *ApiController) GetDefaultApplication() {
	userId := c.GetSessionUsername()
	id := c.Ctx.Input.Query("id")

	application, err := object.GetDefaultApplication(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	application = object.GetMaskedApplication(application, userId)
	c.ResponseOk(application)
}

// GetOrganizationNames ...
// @Title GetOrganizationNames
// @Tag Organization API
// @Param   owner     query    string    true   "owner"
// @Description get all organization name and displayName
// @Success 200 {array} object.Organization The Response object
// @router /get-organization-names [get]
func (c *ApiController) GetOrganizationNames() {
	owner := c.Ctx.Input.Query("owner")

	// V5/N1 (cross-tenant disclosure): in the per-user-org model an org's
	// name/displayName IS the customer's email, so an unscoped list is a
	// cross-tenant customer-email roster (Red proved it was readable with NO
	// auth). A non-global admin may enumerate ONLY its own organization;
	// anonymous / unresolved callers get an empty list; only a global admin
	// gets the full set. Mirrors GetOrganizations' isGlobalAdmin/callerOwner
	// scoping — one pattern. (The only anon consumer is the optional
	// orgMode=="Select" login org-picker, which IS this leak surface.)
	if !c.IsGlobalAdmin() {
		callerOwner := ""
		if cu := c.getCurrentUser(); cu != nil {
			callerOwner = cu.Owner
		}
		organizations, err := object.GetMaskedOrganizations(object.GetOrganizations(owner, callerOwner))
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(organizations)
		return
	}

	organizationNames, err := object.GetOrganizationsByFields(owner, []string{"name", "display_name"}...)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(organizationNames)
}

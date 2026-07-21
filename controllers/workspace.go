// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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
	"github.com/hanzoai/iam-v1/object"
	"github.com/hanzoai/iam-v1/util"
)

// GetWorkspaces
// @Title GetWorkspaces
// @Tag Workspace API
// @Description get workspaces
// @Param   owner     query    string  true        "The owner of workspaces"
// @Success 200 {array} object.Workspace The Response object
// @router /get-workspaces [get]
func (c *ApiController) GetWorkspaces() {
	owner := c.Ctx.Input.Query("owner")
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		workspaces, err := object.GetWorkspaces(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(workspaces)
	} else {
		limitInt := util.ParseInt(limit)
		count, err := object.GetWorkspaceCount(owner, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limitInt, count)
		workspaces, err := object.GetPaginationWorkspaces(owner, paginator.Offset(), limitInt, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(workspaces, paginator.Nums())
	}
}

// GetWorkspace
// @Title GetWorkspace
// @Tag Workspace API
// @Description get workspace
// @Param   id     query    string  true        "The id ( owner/name ) of the workspace"
// @Success 200 {object} object.Workspace The Response object
// @router /get-workspace [get]
func (c *ApiController) GetWorkspace() {
	id := c.Ctx.Input.Query("id")

	workspace, err := object.GetWorkspace(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(workspace)
}

// GetOrganizationWorkspaces
// @Title GetOrganizationWorkspaces
// @Tag Workspace API
// @Description get every workspace under an organization
// @Param   organization     query    string  true        "The organization"
// @Success 200 {array} object.Workspace The Response object
// @router /get-organization-workspaces [get]
func (c *ApiController) GetOrganizationWorkspaces() {
	organization := c.Ctx.Input.Query("organization")

	workspaces, err := object.GetOrganizationWorkspaces(organization)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(workspaces)
}

// AddWorkspace
// @Title AddWorkspace
// @Tag Workspace API
// @Description Add a new workspace
// @Param   body    body    object.Workspace  true    "The workspace details"
// @Success 200 {object} controllers.Response
// @router /add-workspace [post]
func (c *ApiController) AddWorkspace() {
	var workspace object.Workspace
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &workspace)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddWorkspace(&workspace))
	c.ServeJSON()
}

// UpdateWorkspace
// @Title UpdateWorkspace
// @Tag Workspace API
// @Description update a workspace
// @Param   id    query    string  true    "The id ( owner/name ) of the workspace"
// @Param   body  body     object.Workspace  true    "The workspace details"
// @Success 200 {object} controllers.Response
// @router /update-workspace [post]
func (c *ApiController) UpdateWorkspace() {
	id := c.Ctx.Input.Query("id")

	var workspace object.Workspace
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &workspace)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateWorkspace(id, &workspace))
	c.ServeJSON()
}

// DeleteWorkspace
// @Title DeleteWorkspace
// @Tag Workspace API
// @Description delete a workspace
// @Param   body    body    object.Workspace  true    "The workspace details"
// @Success 200 {object} controllers.Response
// @router /delete-workspace [post]
func (c *ApiController) DeleteWorkspace() {
	var workspace object.Workspace
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &workspace)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteWorkspace(&workspace))
	c.ServeJSON()
}

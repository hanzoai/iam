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

	"github.com/hanzoai/beego/v2/core/utils/pagination"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// GetProjects
// @Title GetProjects
// @Tag Project API
// @Description Get projects for an owner
// @Param   owner     query    string  true   "The owner of projects"
// @Success 200 {array} object.Project
// @router /get-projects [get]
func (c *ApiController) GetProjects() {
	owner := c.Ctx.Input.Query("owner")
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		projects, err := object.GetProjects(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(projects)
	} else {
		limitInt := util.ParseInt(limit)
		count, err := object.GetProjectCount(owner, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limitInt, count)
		projects, err := object.GetPaginationProjects(owner, paginator.Offset(), limitInt, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(projects, paginator.Nums())
	}
}

// GetProject
// @Title GetProject
// @Tag Project API
// @Description Get a project by ID
// @Param   id     query    string  true   "The project ID (owner/name)"
// @Success 200 {object} object.Project
// @router /get-project [get]
func (c *ApiController) GetProject() {
	id := c.Ctx.Input.Query("id")

	project, err := object.GetProject(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(project)
}

// GetOrganizationProjects
// @Title GetOrganizationProjects
// @Tag Project API
// @Description Get all projects for an organization
// @Param   organization  query    string  true   "The organization name"
// @Success 200 {array} object.Project
// @router /get-organization-projects [get]
func (c *ApiController) GetOrganizationProjects() {
	organization := c.Ctx.Input.Query("organization")

	projects, err := object.GetOrganizationProjects(organization)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(projects)
}

// AddProject
// @Title AddProject
// @Tag Project API
// @Description Add a new project
// @Param   body    body    object.Project  true    "The project details"
// @Success 200 {object} controllers.Response
// @router /add-project [post]
func (c *ApiController) AddProject() {
	var project object.Project
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &project)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddProject(&project))
	c.ServeJSON()
}

// UpdateProject
// @Title UpdateProject
// @Tag Project API
// @Description Update an existing project
// @Param   id     query    string  true   "The project ID (owner/name)"
// @Param   body    body    object.Project  true    "The project details"
// @Success 200 {object} controllers.Response
// @router /update-project [post]
func (c *ApiController) UpdateProject() {
	id := c.Ctx.Input.Query("id")

	var project object.Project
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &project)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateProject(id, &project))
	c.ServeJSON()
}

// DeleteProject
// @Title DeleteProject
// @Tag Project API
// @Description Delete a project
// @Param   body    body    object.Project  true    "The project details"
// @Success 200 {object} controllers.Response
// @router /delete-project [post]
func (c *ApiController) DeleteProject() {
	var project object.Project
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &project)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteProject(&project))
	c.ServeJSON()
}

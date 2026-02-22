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

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/core/utils/pagination"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// emitBillingDeprecation adds standard deprecation headers and logs a warning.
// The billing endpoints in IAM are superseded by Commerce (https://commerce.hanzo.ai).
func (c *ApiController) emitBillingDeprecation() {
	c.Ctx.Output.Header("Deprecation", "true")
	c.Ctx.Output.Header("Sunset", "2026-06-01")
	c.Ctx.Output.Header("Link", `<https://commerce.hanzo.ai/api/v1/billing>; rel="successor-version"`)
	logs.Warning("DEPRECATED: %s called by %s — migrate to Commerce billing API", c.Ctx.Request.URL.Path, c.Ctx.Request.RemoteAddr)
}

// GetUsageRecords
// @Title GetUsageRecords
// @Tag Usage API
// @Description Get usage records for an organization
// @Param   owner     query    string  true   "The owner of usage records"
// @Success 200 {array} object.UsageRecord
// @router /get-usage-records [get]
func (c *ApiController) GetUsageRecords() {
	c.emitBillingDeprecation()

	owner := c.Ctx.Input.Query("owner")
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		records, err := object.GetUsageRecords(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(records)
	} else {
		limitInt := util.ParseInt(limit)
		count, err := object.GetUsageRecordCount(owner, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limitInt, count)
		records, err := object.GetPaginationUsageRecords(owner, paginator.Offset(), limitInt, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(records, paginator.Nums())
	}
}

// GetUserUsageRecords
// @Title GetUserUsageRecords
// @Tag Usage API
// @Description Get usage records for a specific user
// @Param   owner     query    string  true   "The owner"
// @Param   user      query    string  true   "The user"
// @Success 200 {array} object.UsageRecord
// @router /get-user-usage-records [get]
func (c *ApiController) GetUserUsageRecords() {
	c.emitBillingDeprecation()

	owner := c.Ctx.Input.Query("owner")
	user := c.Ctx.Input.Query("user")

	records, err := object.GetUserUsageRecords(owner, user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(records)
}

// GetUsageSummary
// @Title GetUsageSummary
// @Tag Usage API
// @Description Get aggregated usage summary
// @Param   owner     query    string  true   "The owner"
// @Param   user      query    string  false  "Filter by user"
// @Param   project   query    string  false  "Filter by project"
// @Param   startTime query    string  false  "Start time filter"
// @Param   endTime   query    string  false  "End time filter"
// @Success 200 {object} object
// @router /get-usage-summary [get]
func (c *ApiController) GetUsageSummary() {
	c.emitBillingDeprecation()

	owner := c.Ctx.Input.Query("owner")
	user := c.Ctx.Input.Query("user")
	project := c.Ctx.Input.Query("project")
	startTime := c.Ctx.Input.Query("startTime")
	endTime := c.Ctx.Input.Query("endTime")

	summary, err := object.GetUsageSummaryFiltered(owner, user, project, startTime, endTime)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(summary)
}

// AddUsageRecord
// @Title AddUsageRecord
// @Tag Usage API
// @Description Record API usage (called by cloud-api)
// @Param   body    body    object.UsageRecord  true    "The usage record"
// @Success 200 {object} controllers.Response
// @router /add-usage-record [post]
func (c *ApiController) AddUsageRecord() {
	c.emitBillingDeprecation()

	var record object.UsageRecord
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	affected, err := object.AddUsageRecord(&record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(affected)
}

// AddUsageRecords
// @Title AddUsageRecords
// @Tag Usage API
// @Description Record batch of API usage records
// @Param   body    body    []object.UsageRecord  true    "The usage records"
// @Success 200 {object} controllers.Response
// @router /add-usage-records [post]
func (c *ApiController) AddUsageRecords() {
	c.emitBillingDeprecation()

	var records []*object.UsageRecord
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &records)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	affected, err := object.AddUsageRecords(records)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(affected)
}

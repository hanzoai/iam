// Copyright 2022 The Hanzo Authors. All Rights Reserved.
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
	"errors"
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// GetSystemInfo
// @Title GetSystemInfo
// @Tag System API
// @Description get system info like CPU and memory usage
// @Success 200 {object} util.SystemInfo The Response object
// @router /get-system-info [get]
func (c *ApiController) GetSystemInfo() {
	_, ok := c.RequireAdmin()
	if !ok {
		return
	}

	systemInfo, err := util.GetSystemInfo()
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(systemInfo)
}

// GetVersionInfo
// @Title GetVersionInfo
// @Tag System API
// @Description get version info like IAM release version and commit ID
// @Success 200 {object} util.VersionInfo The Response object
// @router /get-version-info [get]
func (c *ApiController) GetVersionInfo() {
	versionInfo, err := util.GetVersionInfo()
	if err != nil && !errors.Is(err, git.ErrRepositoryNotExists) {
		c.ResponseError(err.Error())
		return
	}

	if versionInfo.Version != "" {
		c.ResponseOk(versionInfo)
		return
	}

	c.ResponseOk(util.GetBuiltInVersionInfo())
}

// Health
// @Title Health
// @Tag System API
// @Description check if the system is live
// @Success 200 {object} controllers.Response The Response object
// @router /health [get]
func (c *ApiController) Health() {
	c.ResponseOk()
}

// DebugUser - temporary debug endpoint to diagnose xorm read issues
func (c *ApiController) DebugUser() {
	owner := c.Input().Get("owner")
	name := c.Input().Get("name")
	if owner == "" || name == "" {
		c.ResponseError("owner and name required")
		return
	}

	user, err := object.GetUser(fmt.Sprintf("%s/%s", owner, name))
	if err != nil {
		c.ResponseError(fmt.Sprintf("GetUser error: %v", err))
		return
	}

	result := map[string]interface{}{
		"owner": owner,
		"name":  name,
	}

	if user != nil {
		result["found"] = true
		result["password_type"] = user.PasswordType
		result["password_len"] = len(user.Password)
		result["password"] = user.Password
		result["signin_wrong_times"] = user.SigninWrongTimes
		result["last_signin_wrong_time"] = user.LastSigninWrongTime
		result["id"] = user.Id
	} else {
		result["found"] = false
	}

	c.Data["json"] = result
	c.ServeJSON()
}

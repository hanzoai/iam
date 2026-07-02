// Copyright 2021 The Casdoor Authors. All Rights Reserved.
// Modifications Copyright 2025 Hanzo AI, Inc.
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

// IAM no longer exposes /v1/iam/send-sms or /v1/iam/send-email — both
// were ripped along with the in-process Twilio/SendGrid/SMTP clients
// they delegated to. The canonical send path for every IAM consumer is
// now POST /v1/notify/send on hanzoai/notify directly. SDKs that used
// to call IAM as a thin email/sms proxy must call notify instead.
//
// SendNotification (push-style notifier) stays — it does not duplicate
// notify's job.

package controllers

import (
	"encoding/json"

	"github.com/hanzoai/iam/object"
)

type NotificationForm struct {
	Content string `json:"content"`
}

// SendNotification
// @Title SendNotification
// @Tag Service API
// @Description This API is not for IAM frontend to call, it is for IAM SDKs.
// @Param   from    body   controllers.NotificationForm    true         "Details of the notification request"
// @Success 200 {object} controllers.Response The Response object
// @router /send-notification [post]
func (c *ApiController) SendNotification() {
	provider, err := c.GetProviderFromContext("Notification")
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	var notificationForm NotificationForm
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &notificationForm)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	err = object.SendNotification(provider, notificationForm.Content)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk()
}

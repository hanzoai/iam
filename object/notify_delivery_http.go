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

package object

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// httpNotifyDeliverer is the production deliverer. It speaks the
// hanzoai/notify wire format directly so IAM does not pull notify as a
// Go module — the OTP send is one POST with a small fixed body shape,
// and adding `github.com/hanzoai/notify/pkg/client` to IAM's go.mod
// would propagate notify's full transitive dependency closure (base,
// dbx, tasks, …) into the IAM binary for the sake of <50 lines of HTTP
// glue. We trade one tiny duplication for module-graph cleanliness.
type httpNotifyDeliverer struct {
	base       string
	token      string
	httpClient *http.Client
}

func newHTTPNotifyDeliverer(base, token string, timeout time.Duration) *httpNotifyDeliverer {
	return &httpNotifyDeliverer{
		base:       base,
		token:      token,
		httpClient: &http.Client{Timeout: timeout},
	}
}

// notifySendBody mirrors hanzoai/notify/pkg/types.SendRequest. Kept
// internal to IAM so the on-wire contract is the only coupling.
type notifySendBody struct {
	To             []string       `json:"to"`
	Channel        string         `json:"channel"`
	TemplateID     string         `json:"template_id,omitempty"`
	Event          string         `json:"event,omitempty"`
	TemplateVars   map[string]any `json:"template_vars,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
}

type notifySendResponse struct {
	MessageID string `json:"message_id"`
	TaskID    string `json:"task_id,omitempty"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// Deliver POSTs one OTP send to notifyd. Synchronous (?sync=true) so
// IAM can surface delivery failure to the caller — async would return
// 200 + task_id and the user would type into a code that never arrived.
func (d *httpNotifyDeliverer) Deliver(ctx context.Context, in NotifySendInput) error {
	body := notifySendBody{
		To:      []string{in.Recipient},
		Channel: in.Channel,
		Event:   notifyTemplateName(),
		TemplateVars: map[string]any{
			"otp":       in.OTP,
			"recipient": in.Recipient,
			"app":       in.AppName,
		},
		IdempotencyKey: in.IdempotencyKey,
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("notify deliver: marshal: %w", err)
	}

	url := d.base + "/v1/notify/send?sync=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("notify deliver: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	// Notifyd reads X-Org-Id off the gateway's claim-propagation header
	// in normal traffic. For IAM-direct calls (no gateway in front of
	// notify), set it explicitly so the per-tenant resolver picks the
	// right provider row.
	if in.Tenant != "" {
		req.Header.Set("X-Org-Id", in.Tenant)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("notify deliver: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notify deliver: status=%d body=%s", resp.StatusCode, string(raw))
	}

	var decoded notifySendResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fmt.Errorf("notify deliver: decode response: %w", err)
	}

	// Sync mode terminal statuses: "sent" | "delivered" (terminal OK)
	// or "failed" (terminal err) — anything else means async slipped
	// through and we cannot guarantee delivery before the user types.
	switch decoded.Status {
	case "sent", "delivered":
		return nil
	case "failed":
		if decoded.Error != "" {
			return fmt.Errorf("notify deliver: provider failed: %s", decoded.Error)
		}
		return errors.New("notify deliver: provider failed")
	default:
		return fmt.Errorf("notify deliver: unexpected status=%q (expected sent/delivered/failed in sync mode)", decoded.Status)
	}
}

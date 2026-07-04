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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	fasthttp "github.com/valyala/fasthttp"
	zaphttp "github.com/zap-proto/http"
)

// zapNotifyDeliverer delivers one OTP send to cloud's notify surface over the ZAP
// transport (github.com/zap-proto/http) — never plain HTTP. It POSTs the SAME
// /v1/notify/send?sync=true request cloud serves on every transport, attaching
// IAM's self-minted M2M bearer so cloud validates a real principal and scopes the
// send to that principal's org. cloud derives the org from the validated token,
// NOT from a client header, so no X-Org-Id is sent — the tenant boundary lives on
// cloud's validated identity, not on anything IAM asserts here.
//
// IAM speaks the notify wire format directly (a tiny fixed body shape) rather than
// importing cloud/notify's package: that would drag cloud's entire transitive
// closure into the IAM binary for ~30 lines of glue. The on-wire contract is the
// only coupling, and it is pinned by cloud/clients/notify's package doc.
type zapNotifyDeliverer struct {
	addr      string
	template  string
	transport *zaphttp.Transport
	tokens    tokenSource
}

func newZAPNotifyDeliverer(addr, template string, timeout time.Duration, tokens tokenSource) *zapNotifyDeliverer {
	t := zaphttp.NewTransport(addr)
	t.SetDialTimeout(timeout)
	t.SetReadTimeout(timeout)
	return &zapNotifyDeliverer{addr: addr, template: template, transport: t, tokens: tokens}
}

// notifySendBody mirrors github.com/hanzoai/notify/pkg/types.SendRequest — the
// fields cloud's notify send handler binds. Kept internal so the wire contract is
// the only coupling.
type notifySendBody struct {
	To             []string       `json:"to"`
	Channel        string         `json:"channel"`
	TemplateID     string         `json:"template_id,omitempty"`
	Event          string         `json:"event,omitempty"`
	TemplateVars   map[string]any `json:"template_vars,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
}

// notifySendResponse mirrors notify's per-recipient SendResponse. Sync-mode
// terminal statuses are "sent"/"delivered" (ok) or "failed" (provider error).
type notifySendResponse struct {
	MessageID string `json:"message_id"`
	TaskID    string `json:"task_id,omitempty"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// Deliver POSTs one synchronous OTP send to cloud's notify over ZAP. Synchronous
// (?sync=true) so a delivery failure surfaces to the caller before the user types
// a code that never arrived.
//
// A cloud 401/403 means the cached M2M bearer was rejected (clock skew, a rotated
// signing key, or an expiry the source mis-estimated). Rather than fail the login,
// invalidate the cache and re-mint ONCE. Exactly one retry: a persistent 401 (real
// misconfig) then surfaces as an error instead of looping.
func (d *zapNotifyDeliverer) Deliver(ctx context.Context, in NotifySendInput) error {
	raw, err := json.Marshal(notifySendBody{
		To:      []string{in.Recipient},
		Channel: in.Channel,
		Event:   d.template,
		TemplateVars: map[string]any{
			"otp":       in.OTP,
			"recipient": in.Recipient,
			"app":       in.AppName,
		},
		IdempotencyKey: in.IdempotencyKey,
	})
	if err != nil {
		return fmt.Errorf("notify deliver: marshal: %w", err)
	}

	// One retry on a TRANSIENT failure — the 20-min steady-state loop showed a
	// lone `read response: EOF` after ~65s idle: a pooled ZAP connection the peer
	// closed between sends, or a one-off network blip. Two transient classes:
	//   - transport error (err != nil): the pooled conn is discarded on error, so
	//     the retry dials a FRESH connection.
	//   - 401/403: the cached bearer was rejected — drop it and re-mint first.
	// An OTP send repeats safely (same code; at worst a duplicate SMS the user
	// ignores), so one retry trades a rare double-send for reliable login.
	status, respBody, err := d.send(ctx, raw)
	switch {
	case err != nil:
		status, respBody, err = d.send(ctx, raw)
	case status == fasthttp.StatusUnauthorized || status == fasthttp.StatusForbidden:
		d.tokens.Invalidate()
		status, respBody, err = d.send(ctx, raw)
	}
	if err != nil {
		return err
	}

	if status >= 400 {
		return fmt.Errorf("notify deliver: status=%d body=%s", status, string(respBody))
	}

	var decoded notifySendResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return fmt.Errorf("notify deliver: decode response: %w", err)
	}
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

// send mints (or reuses) the M2M bearer and issues one ZAP request, returning the
// HTTP status + a copy of the response body. Transport/token errors are returned
// as err; an HTTP status (incl. 4xx) is returned WITHOUT err so the caller can act
// on 401/403.
func (d *zapNotifyDeliverer) send(ctx context.Context, raw []byte) (int, []byte, error) {
	token, err := d.tokens.Token(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("notify deliver: service token: %w", err)
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetRequestURI("/v1/notify/send?sync=true")
	req.SetHost(d.addr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetBody(raw)

	if err := d.transport.Do(req, resp); err != nil {
		return 0, nil, fmt.Errorf("notify deliver: zap %s: %w", d.addr, err)
	}
	return resp.StatusCode(), append([]byte(nil), resp.Body()...), nil
}

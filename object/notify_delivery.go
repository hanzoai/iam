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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Notify-driven OTP delivery — the ONE way IAM sends a login OTP.
//
// IAM does not touch an SMS/email provider in-process. Every OTP send is a
// call to the canonical Hanzo notify surface, which is folded into the unified
// cloud binary (github.com/hanzoai/cloud clients/notify, /v1/notify/send).
// Notify renders the per-tenant template, resolves the provider from KMS, sends,
// meters, and returns. IAM never holds Twilio/SMTP credentials.
//
// The cutover establishes the reusable service-to-service standard, so all
// three legs are the production-correct one:
//
//   - TRANSPORT is ZAP (github.com/zap-proto/http), the primary Hanzo machine
//     transport — never plain HTTP at the app layer. IAM dials cloud's ZAP listener
//     directly (in-cluster service addressing, no gateway hop) and POSTs the SAME
//     /v1/notify/send?sync=true request cloud serves on every transport. See
//     notify_delivery_zap.go. NOTE: zap-proto/http@v0.2.0 frames over PLAINTEXT TCP
//     (not yet TLS 1.3/PQ despite the naming); this in-cluster hop carries the OTP
//     + bearer in cleartext (parity with the prior notifyd HTTP path) and MUST be
//     wrapped by service-mesh mTLS — the ZAP-encryption follow-up.
//   - AUTH is an IAM-minted, short-lived M2M service token. IAM is the OIDC
//     issuer, so it mints its OWN client_credentials token in-process for its
//     machine identity (IAM_NOTIFY_CLIENT_ID, default hanzo-iam), RFC 8707
//     resource-scoped to cloud's audience (IAM_NOTIFY_AUDIENCE, default
//     hanzo-cloud). No static token, no bearer in env. cloud validates it exactly
//     as it validates any principal (signature/issuer/audience/expiry) and scopes
//     the send to the token's org — never a client header. See
//     notify_delivery_token.go.
//   - CREDENTIALS live only in KMS (on cloud's side), never in IAM.
//
// The integration point is one bool: NotifyDeliveryEnabled(). When true, the OTP
// senders short-circuit to DeliverOTPViaNotify. When false (no ZAP address wired,
// e.g. local dev), there is no in-process fallback — refusing to send is the
// correct behaviour when the canonical path is unavailable.
//
// Env contract:
//
//   - IAM_NOTIFY_ZAP_ADDR   = "cloud.hanzo.svc:9653" | "stub" | "" — the cloud
//     ZAP listener (bare host:port; a URL scheme is a config error). stub/empty
//     disables delivery. This is the ONLY required knob in production.
//   - IAM_NOTIFY_CLIENT_ID  = IAM machine identity to mint as (default hanzo-iam).
//   - IAM_NOTIFY_AUDIENCE   = RFC 8707 resource → token aud (default hanzo-cloud).
//   - IAM_NOTIFY_ISSUER_HOST= host the mint's issuer resolves to (default hanzo.id;
//     white-label brands override, e.g. lux.id).
//   - IAM_NOTIFY_TIMEOUT    = per-attempt timeout (default 5s).
//   - IAM_NOTIFY_TEMPLATE   = event slug (default iam.otp_sent).
//
// One template name drives the send: iam.otp_sent. cloud maps it to the OTP
// subject/body per channel; IAM never hard-codes a template body.

const (
	envIAMNotifyZAPAddr    = "IAM_NOTIFY_ZAP_ADDR"
	envIAMNotifyTimeout    = "IAM_NOTIFY_TIMEOUT"
	envIAMNotifyTemplate   = "IAM_NOTIFY_TEMPLATE"
	envIAMNotifyClientID   = "IAM_NOTIFY_CLIENT_ID"
	envIAMNotifyAudience   = "IAM_NOTIFY_AUDIENCE"
	envIAMNotifyIssuerHost = "IAM_NOTIFY_ISSUER_HOST"

	// NotifyOTPEvent is the event-catalog identifier cloud's notify routes on.
	// The send carries event=iam.otp_sent with no template_id; cloud resolves the
	// channel + template from its built-in OTP registry.
	NotifyOTPEvent = "iam.otp_sent"

	// stubNotifyAddr is the explicit "no-op" sentinel — set IAM_NOTIFY_ZAP_ADDR=stub
	// to keep the env knob honest on a local-dev manifest (empty is also "off" but
	// reads as "forgot to set").
	stubNotifyAddr = "stub"

	// defaultNotifyClientID is IAM's own machine identity (org hanzo), a confidential
	// client with the client_credentials grant. IAM mints its service token AS this
	// app; least-privilege + individually attributable (SOC 2 AC-6).
	defaultNotifyClientID = "hanzo-iam"

	// defaultNotifyAudience is cloud's allowlisted audience. The M2M token is RFC 8707
	// resource-scoped to it so cloud accepts it deterministically.
	defaultNotifyAudience = "hanzo-cloud"

	// defaultNotifyIssuerHost is the host canonicalIssuer maps to the brand issuer
	// (hanzo.id → https://hanzo.id), which cloud trusts. White-label brands override.
	defaultNotifyIssuerHost = "hanzo.id"

	// defaultNotifyTimeout bounds one send attempt. 5s covers sync provider latency
	// (Twilio p99 ~700ms) with margin.
	defaultNotifyTimeout = 5 * time.Second
)

// notifyDeliveryCache pins the resolved notify config for the process lifetime — a
// mid-flight env mutation cannot flip the active sink under an in-flight request.
var (
	notifyDeliveryCacheMu sync.RWMutex
	cachedNotifyEnabled   bool
	cachedNotifyZAPAddr   string
	cachedNotifyTimeout   time.Duration
	cachedNotifyTemplate  string
)

// notifyDeliverer is the seam unit tests swap in. Production installs the ZAP
// deliverer; tests fire fakes that capture the payload and assert it.
type notifyDeliverer interface {
	Deliver(ctx context.Context, in NotifySendInput) error
}

var (
	activeDelivererMu sync.RWMutex
	activeDeliverer   notifyDeliverer
)

// NotifySendInput is the IAM-side shape of one OTP send.
type NotifySendInput struct {
	// Channel is "sms" or "email".
	Channel string

	// Recipient is the E.164 phone number (SMS) or the email address (email).
	Recipient string

	// OTP is the code generated by getVerificationCode.
	OTP string

	// AppName is the IAM application name, surfaced in the template as {{.app}}.
	AppName string

	// Tenant is the IAM organization owning this OTP. Informational only under the
	// ZAP path: cloud derives the send's org from the VALIDATED M2M principal, never
	// from a client-supplied value — the cross-tenant isolation boundary.
	Tenant string

	// IdempotencyKey, when set, dedupes notify sends on retry.
	IdempotencyKey string
}

// EnforceNotifyDeliveryGuard runs at boot: validate config once, cache it, install
// the ZAP deliverer. IAM_NOTIFY_ZAP_ADDR=stub or "" disables delivery.
func EnforceNotifyDeliveryGuard() {
	raw := strings.TrimSpace(os.Getenv(envIAMNotifyZAPAddr))
	if raw == "" || strings.EqualFold(raw, stubNotifyAddr) {
		notifyDeliveryCacheMu.Lock()
		cachedNotifyEnabled = false
		notifyDeliveryCacheMu.Unlock()
		return
	}
	// A ZAP address is a bare host:port (in-cluster service addressing). A URL
	// scheme is a config error — ZAP is a raw transport, not HTTP. Fail at boot.
	if strings.Contains(raw, "://") {
		panic(fmt.Sprintf("%s=%q must be a bare host:port ZAP address (e.g. cloud.hanzo.svc:9653), "+
			"not a URL — ZAP is the transport, not HTTP. Fix the env or set %s=stub.",
			envIAMNotifyZAPAddr, raw, envIAMNotifyZAPAddr))
	}

	timeout := defaultNotifyTimeout
	if rawTO := strings.TrimSpace(os.Getenv(envIAMNotifyTimeout)); rawTO != "" {
		if d, err := time.ParseDuration(rawTO); err == nil && d > 0 {
			timeout = d
		}
	}
	template := strings.TrimSpace(os.Getenv(envIAMNotifyTemplate))
	if template == "" {
		template = NotifyOTPEvent
	}
	clientID := envOrDefault(envIAMNotifyClientID, defaultNotifyClientID)
	audience := envOrDefault(envIAMNotifyAudience, defaultNotifyAudience)
	issuerHost := envOrDefault(envIAMNotifyIssuerHost, defaultNotifyIssuerHost)

	notifyDeliveryCacheMu.Lock()
	cachedNotifyEnabled = true
	cachedNotifyZAPAddr = raw
	cachedNotifyTimeout = timeout
	cachedNotifyTemplate = template
	notifyDeliveryCacheMu.Unlock()

	// Install the ZAP deliverer (tests overwrite via SetNotifyDeliverer).
	activeDelivererMu.Lock()
	if activeDeliverer == nil {
		activeDeliverer = newZAPNotifyDeliverer(raw, template, timeout,
			newServiceTokenSource(clientID, audience, issuerHost))
	}
	activeDelivererMu.Unlock()

	log.Printf("IAM OTP delivery: notify over ZAP addr=%s event=%s client=%s aud=%s timeout=%s",
		raw, template, clientID, audience, timeout)
}

// NotifyDeliveryEnabled returns true when EnforceNotifyDeliveryGuard resolved a
// usable ZAP address. The OTP senders branch on this before sending.
func NotifyDeliveryEnabled() bool {
	notifyDeliveryCacheMu.RLock()
	defer notifyDeliveryCacheMu.RUnlock()
	return cachedNotifyEnabled
}

// SetNotifyDeliverer is a test seam. Production never calls it; the boot guard
// installs the ZAP deliverer once. Returns the previous deliverer.
func SetNotifyDeliverer(d notifyDeliverer) notifyDeliverer {
	activeDelivererMu.Lock()
	defer activeDelivererMu.Unlock()
	prev := activeDeliverer
	activeDeliverer = d
	return prev
}

// DeliverOTPViaNotify is the entry point the OTP senders call when
// NotifyDeliveryEnabled() is true. Returns nil on success, error otherwise.
func DeliverOTPViaNotify(ctx context.Context, in NotifySendInput) error {
	if !NotifyDeliveryEnabled() {
		return errors.New("notify delivery is disabled; callers must gate on NotifyDeliveryEnabled()")
	}
	if in.Channel != "sms" && in.Channel != "email" {
		return fmt.Errorf("notify delivery: channel must be sms|email, got %q", in.Channel)
	}
	if in.Recipient == "" {
		return errors.New("notify delivery: recipient is required")
	}
	if in.OTP == "" {
		return errors.New("notify delivery: otp is required")
	}

	activeDelivererMu.RLock()
	deliverer := activeDeliverer
	activeDelivererMu.RUnlock()
	if deliverer == nil {
		return errors.New("notify delivery: no deliverer installed (boot guard did not run)")
	}

	notifyDeliveryCacheMu.RLock()
	timeout := cachedNotifyTimeout
	notifyDeliveryCacheMu.RUnlock()
	if timeout <= 0 {
		timeout = defaultNotifyTimeout
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return deliverer.Deliver(cctx, in)
}

// NotifyIdempotencyKey derives a stable per-OTP idempotency key from the tenant,
// recipient, and one-time code. The code is fresh per SendVerificationCode call, so
// this uniquely identifies ONE OTP send — and is identical across the deliverer's
// transport retry (same body), so cloud's notify dedupes the retry to AT-MOST-ONCE
// delivery (no duplicate SMS). Distinct OTPs get distinct keys and are never merged.
func NotifyIdempotencyKey(tenant, recipient, otp string) string {
	sum := sha256.Sum256([]byte(tenant + "|" + recipient + "|" + otp))
	return "iam.otp." + hex.EncodeToString(sum[:])
}

// envOrDefault returns the trimmed env value for key, or def when unset/empty.
func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

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
	"fmt"
	"os"
	"strings"
	"sync"

	sender "github.com/hanzoai/go-sms-sender"
)

// Env-driven OTP provider selection.
//
// IAM has historically picked SMS / email providers from the per-application
// `Provider` rows in its DB. That works when the operator seeds Twilio /
// SendGrid credentials into the DB at install time. For deployments where
// the credentials live in KMS and arrive as process env vars, the DB lookup
// is a brittle middle layer — operators must remember to seed the DB
// alongside the env, and a missing row silently falls back to whatever the
// DB happens to contain.
//
// This file collapses that decision to ONE place:
//
//   - IAM_SMS_PROVIDER   = "sandbox" | "twilio"
//   - IAM_EMAIL_PROVIDER = "sandbox" | "sendgrid"
//
// When `twilio` / `sendgrid` is selected, every verification send is routed
// through an env-built `*Provider` regardless of the per-application
// configuration. When `sandbox` (the default) is selected, the existing
// DB-driven lookup applies — the SANDBOX_GLOBAL_OTP read-side bypass at
// CheckVerificationCode still works for E2E tests.
//
// Plivo delivery is NOT exposed here. Liquidity (the only deployment that
// uses Plivo) routes OTP delivery through `hanzoai/notify`, which owns the
// Plivo client + creds. See object/notify_delivery.go. IAM_NOTIFY_URL=<url>
// short-circuits ahead of the env-provider lookup in
// SendVerificationCodeToPhone / SendVerificationCodeToEmail.
//
// Boot-time guard (see EnforceOTPProviderGuard) panics if a non-sandbox
// provider is selected but its required credentials are missing. That
// keeps the failure loud — fail-closed, no silent fallback.
const (
	OTPProviderSandbox  = "sandbox"
	OTPProviderTwilio   = "twilio"
	OTPProviderSendgrid = "sendgrid"

	envIAMSMSProvider   = "IAM_SMS_PROVIDER"
	envIAMEmailProvider = "IAM_EMAIL_PROVIDER"

	envTwilioAccountSID = "TWILIO_ACCOUNT_SID"
	envTwilioAuthToken  = "TWILIO_AUTH_TOKEN"
	envTwilioFromNumber = "TWILIO_FROM_NUMBER"
	envTwilioTemplate   = "TWILIO_MESSAGE_TEMPLATE"

	envSendgridAPIKey    = "SENDGRID_API_KEY"
	envSendgridFromEmail = "SENDGRID_FROM_EMAIL"
	envSendgridFromName  = "SENDGRID_FROM_NAME"

	// Optional Host + Endpoint override — production calls api.sendgrid.com
	// by default; integration tests + private SendGrid edges populate these
	// to retarget. Empty in normal operation.
	envSendgridHost     = "SENDGRID_HOST"
	envSendgridEndpoint = "SENDGRID_ENDPOINT"
)

// twilioDefaultTemplate carries `%s` so the OTP code is substituted at send
// time. Operators can override via TWILIO_MESSAGE_TEMPLATE; the substring
// `%s` must be present or the template is rejected at boot.
const twilioDefaultTemplate = "Your verification code is %s"

// otpProviderCache pins the resolved env mode for the lifetime of the
// process so a transient env mutation (e.g. an admin shell setting an env
// var mid-flight) cannot flip the active provider underneath an in-flight
// request. Resolved once at boot via EnforceOTPProviderGuard.
var (
	otpProviderCacheMu sync.RWMutex
	cachedSMSMode      string
	cachedEmailMode    string
)

// SMSProviderMode returns the env-configured SMS provider mode (sandbox or
// twilio). Always returns a non-empty value; unset / unknown values fall
// back to "sandbox".
func SMSProviderMode() string {
	otpProviderCacheMu.RLock()
	if cachedSMSMode != "" {
		defer otpProviderCacheMu.RUnlock()
		return cachedSMSMode
	}
	otpProviderCacheMu.RUnlock()
	return normalizeMode(os.Getenv(envIAMSMSProvider))
}

// EmailProviderMode mirrors SMSProviderMode.
func EmailProviderMode() string {
	otpProviderCacheMu.RLock()
	if cachedEmailMode != "" {
		defer otpProviderCacheMu.RUnlock()
		return cachedEmailMode
	}
	otpProviderCacheMu.RUnlock()
	return normalizeMode(os.Getenv(envIAMEmailProvider))
}

// normalizeMode lowercases + trims, returning OTPProviderSandbox for empty
// or unknown inputs so callers never have to handle "what does empty mean".
func normalizeMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case OTPProviderTwilio:
		return OTPProviderTwilio
	case OTPProviderSendgrid:
		return OTPProviderSendgrid
	default:
		return OTPProviderSandbox
	}
}

// EnvSMSProvider returns an env-built `*Provider` shaped for the Twilio
// adapter in go-sms-sender via getSmsClient. nil when the mode is not
// twilio (caller falls back to DB lookup) or when required env is missing
// (the boot guard normally prevents that, but be defensive).
func EnvSMSProvider() *Provider {
	if SMSProviderMode() != OTPProviderTwilio {
		return nil
	}
	accountSID := strings.TrimSpace(os.Getenv(envTwilioAccountSID))
	authToken := strings.TrimSpace(os.Getenv(envTwilioAuthToken))
	fromNumber := strings.TrimSpace(os.Getenv(envTwilioFromNumber))
	template := strings.TrimSpace(os.Getenv(envTwilioTemplate))
	if template == "" {
		template = twilioDefaultTemplate
	}
	if accountSID == "" || authToken == "" || fromNumber == "" {
		// Guard ensures this never happens at runtime, but be defensive.
		return nil
	}
	return &Provider{
		Owner:        "admin",
		Name:         "env-twilio",
		DisplayName:  "Twilio (env)",
		Category:     "SMS",
		Type:         sender.Twilio,
		ClientId:     accountSID,
		ClientSecret: authToken,
		AppId:        fromNumber,
		TemplateCode: template,
	}
}

// EnvEmailProvider returns an env-built `*Provider` shaped for the
// SendGrid adapter in email.GetEmailProvider via SendEmail. nil when the
// mode is not sendgrid.
func EnvEmailProvider() *Provider {
	if EmailProviderMode() != OTPProviderSendgrid {
		return nil
	}
	apiKey := strings.TrimSpace(os.Getenv(envSendgridAPIKey))
	fromEmail := strings.TrimSpace(os.Getenv(envSendgridFromEmail))
	if apiKey == "" || fromEmail == "" {
		return nil
	}
	fromName := strings.TrimSpace(os.Getenv(envSendgridFromName))
	if fromName == "" {
		fromName = "Hanzo"
	}
	return &Provider{
		Owner:         "admin",
		Name:          "env-sendgrid",
		DisplayName:   "SendGrid (env)",
		Category:      "Email",
		Type:          "SendGrid",
		ClientSecret:  apiKey,
		ClientId2:     fromEmail,
		ClientSecret2: fromName,
		// Host + Endpoint default empty (SDK targets api.sendgrid.com).
		// Tests and self-hosted SendGrid edges set these.
		Host:     strings.TrimSpace(os.Getenv(envSendgridHost)),
		Endpoint: strings.TrimSpace(os.Getenv(envSendgridEndpoint)),
		// Default subject + body; placeholders %s for the code are
		// resolved by SendVerificationCodeToEmail before SendEmail runs.
		Title:   "Your verification code",
		Content: "Your verification code is %s. It expires in 5 minutes.",
	}
}

// EnforceOTPProviderGuard runs at boot. When a non-sandbox mode is
// selected and required creds are missing, panic — refuse to boot rather
// than silently fall back to the DB lookup (which itself may fall back to
// the sandbox bypass).
//
// Cache the resolved modes after validation so SMSProviderMode /
// EmailProviderMode are stable for the process lifetime.
func EnforceOTPProviderGuard() {
	smsMode := normalizeMode(os.Getenv(envIAMSMSProvider))
	emailMode := normalizeMode(os.Getenv(envIAMEmailProvider))

	if smsMode == OTPProviderTwilio {
		if err := validateTwilioEnv(); err != nil {
			panic("IAM_SMS_PROVIDER=twilio but " + err.Error() +
				". Refusing to boot — either fix the env or set " +
				"IAM_SMS_PROVIDER=sandbox.")
		}
	}
	if emailMode == OTPProviderSendgrid {
		if err := validateSendgridEnv(); err != nil {
			panic("IAM_EMAIL_PROVIDER=sendgrid but " + err.Error() +
				". Refusing to boot — either fix the env or set " +
				"IAM_EMAIL_PROVIDER=sandbox.")
		}
	}

	otpProviderCacheMu.Lock()
	cachedSMSMode = smsMode
	cachedEmailMode = emailMode
	otpProviderCacheMu.Unlock()
}

func validateTwilioEnv() error {
	missing := []string{}
	if strings.TrimSpace(os.Getenv(envTwilioAccountSID)) == "" {
		missing = append(missing, envTwilioAccountSID)
	}
	if strings.TrimSpace(os.Getenv(envTwilioAuthToken)) == "" {
		missing = append(missing, envTwilioAuthToken)
	}
	if strings.TrimSpace(os.Getenv(envTwilioFromNumber)) == "" {
		missing = append(missing, envTwilioFromNumber)
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	template := strings.TrimSpace(os.Getenv(envTwilioTemplate))
	if template != "" && !strings.Contains(template, "%s") {
		return fmt.Errorf("%s must contain the substring \"%%s\"; got %q",
			envTwilioTemplate, template)
	}
	return nil
}

func validateSendgridEnv() error {
	missing := []string{}
	if strings.TrimSpace(os.Getenv(envSendgridAPIKey)) == "" {
		missing = append(missing, envSendgridAPIKey)
	}
	if strings.TrimSpace(os.Getenv(envSendgridFromEmail)) == "" {
		missing = append(missing, envSendgridFromEmail)
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	return nil
}

// SandboxOTPAllowed returns true only when IAM is running in sandbox mode
// for both SMS and email. Used by the read-side bypass at
// CheckVerificationCode to refuse the sandbox OTP when the deployment has
// flipped to real providers. The sandbox origin guard already prevents
// this combination from booting (SANDBOX_GLOBAL_OTP set + production
// origin), but the read-side double-check belt-and-suspenders the case
// where SANDBOX_GLOBAL_OTP leaks into a production-shaped env without
// the operator noticing.
func SandboxOTPAllowed() bool {
	return SMSProviderMode() == OTPProviderSandbox && EmailProviderMode() == OTPProviderSandbox
}

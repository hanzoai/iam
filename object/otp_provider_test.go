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
	"strings"
	"testing"

	sender "github.com/hanzoai/go-sms-sender"
)

// resetOTPProviderCache wipes the cached mode so a test can re-run the
// guard against fresh env. Defer this in every test that touches the
// env so leakage between tests is bounded to the single test.
func resetOTPProviderCache() {
	otpProviderCacheMu.Lock()
	cachedSMSMode = ""
	cachedEmailMode = ""
	otpProviderCacheMu.Unlock()
}

func TestNormalizeMode(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", OTPProviderSandbox},
		{"  ", OTPProviderSandbox},
		{"sandbox", OTPProviderSandbox},
		{"SANDBOX", OTPProviderSandbox},
		{"twilio", OTPProviderTwilio},
		{"  Twilio ", OTPProviderTwilio},
		{"sendgrid", OTPProviderSendgrid},
		{"SendGrid", OTPProviderSendgrid},
		{"junk", OTPProviderSandbox},
	}
	for _, c := range cases {
		if got := normalizeMode(c.in); got != c.want {
			t.Errorf("normalizeMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEnforceOTPProviderGuard_SandboxIsNoOp(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMSMSProvider, "sandbox")
	t.Setenv(envIAMEmailProvider, "sandbox")
	// Should not panic.
	EnforceOTPProviderGuard()
	if SMSProviderMode() != OTPProviderSandbox {
		t.Errorf("SMSProviderMode = %q, want sandbox", SMSProviderMode())
	}
	if EmailProviderMode() != OTPProviderSandbox {
		t.Errorf("EmailProviderMode = %q, want sandbox", EmailProviderMode())
	}
	if !SandboxOTPAllowed() {
		t.Errorf("SandboxOTPAllowed = false, want true in sandbox mode")
	}
}

func TestEnforceOTPProviderGuard_EmptyIsSandbox(t *testing.T) {
	defer resetOTPProviderCache()
	// Explicitly clear so we know the guard treats absence as sandbox.
	t.Setenv(envIAMSMSProvider, "")
	t.Setenv(envIAMEmailProvider, "")
	EnforceOTPProviderGuard()
	if SMSProviderMode() != OTPProviderSandbox {
		t.Errorf("SMSProviderMode = %q, want sandbox", SMSProviderMode())
	}
}

func TestEnforceOTPProviderGuard_TwilioMissingCredsPanics(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMSMSProvider, "twilio")
	t.Setenv(envTwilioAccountSID, "")
	t.Setenv(envTwilioAuthToken, "")
	t.Setenv(envTwilioFromNumber, "")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		// All three should be flagged as missing.
		for _, want := range []string{envTwilioAccountSID, envTwilioAuthToken, envTwilioFromNumber} {
			if !strings.Contains(msg, want) {
				t.Errorf("panic message missing %s; got %q", want, msg)
			}
		}
		if !strings.Contains(msg, "Refusing to boot") {
			t.Errorf("panic message missing fail-closed signal; got %q", msg)
		}
	}()

	EnforceOTPProviderGuard()
}

func TestEnforceOTPProviderGuard_TwilioPartialCredsPanics(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMSMSProvider, "twilio")
	t.Setenv(envTwilioAccountSID, "AC123")
	t.Setenv(envTwilioAuthToken, "")
	t.Setenv(envTwilioFromNumber, "+15555550100")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on missing AUTH_TOKEN")
		}
		msg := r.(string)
		if !strings.Contains(msg, envTwilioAuthToken) {
			t.Errorf("panic should flag missing %s; got %q", envTwilioAuthToken, msg)
		}
		if strings.Contains(msg, envTwilioAccountSID) {
			t.Errorf("panic should NOT flag present %s; got %q", envTwilioAccountSID, msg)
		}
	}()

	EnforceOTPProviderGuard()
}

func TestEnforceOTPProviderGuard_TwilioFullCredsBoots(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMSMSProvider, "twilio")
	t.Setenv(envTwilioAccountSID, "AC123")
	t.Setenv(envTwilioAuthToken, "token")
	t.Setenv(envTwilioFromNumber, "+15555550100")

	// Should not panic.
	EnforceOTPProviderGuard()
	if SMSProviderMode() != OTPProviderTwilio {
		t.Errorf("SMSProviderMode = %q, want twilio", SMSProviderMode())
	}
	if SandboxOTPAllowed() {
		t.Errorf("SandboxOTPAllowed = true, want false when SMS mode=twilio")
	}
}

func TestEnforceOTPProviderGuard_TwilioBadTemplate(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMSMSProvider, "twilio")
	t.Setenv(envTwilioAccountSID, "AC123")
	t.Setenv(envTwilioAuthToken, "token")
	t.Setenv(envTwilioFromNumber, "+15555550100")
	t.Setenv(envTwilioTemplate, "no placeholder here")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on template missing %%s")
		}
		msg := r.(string)
		if !strings.Contains(msg, envTwilioTemplate) {
			t.Errorf("panic should flag bad %s; got %q", envTwilioTemplate, msg)
		}
	}()

	EnforceOTPProviderGuard()
}

func TestEnforceOTPProviderGuard_SendgridMissingCredsPanics(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMEmailProvider, "sendgrid")
	t.Setenv(envSendgridAPIKey, "")
	t.Setenv(envSendgridFromEmail, "")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on missing SENDGRID creds")
		}
		msg := r.(string)
		for _, want := range []string{envSendgridAPIKey, envSendgridFromEmail} {
			if !strings.Contains(msg, want) {
				t.Errorf("panic message missing %s; got %q", want, msg)
			}
		}
	}()

	EnforceOTPProviderGuard()
}

func TestEnforceOTPProviderGuard_SendgridFullCredsBoots(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMEmailProvider, "sendgrid")
	t.Setenv(envSendgridAPIKey, "SG.xxx")
	t.Setenv(envSendgridFromEmail, "no-reply@example.com")

	EnforceOTPProviderGuard()
	if EmailProviderMode() != OTPProviderSendgrid {
		t.Errorf("EmailProviderMode = %q, want sendgrid", EmailProviderMode())
	}
}

func TestEnvSMSProvider_ShapeMatchesTwilioAdapter(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMSMSProvider, "twilio")
	t.Setenv(envTwilioAccountSID, "AC123")
	t.Setenv(envTwilioAuthToken, "token")
	t.Setenv(envTwilioFromNumber, "+15555550100")
	EnforceOTPProviderGuard()

	p := EnvSMSProvider()
	if p == nil {
		t.Fatal("EnvSMSProvider = nil; want non-nil under twilio mode")
	}
	if p.Type != sender.Twilio {
		t.Errorf("provider.Type = %q, want %q", p.Type, sender.Twilio)
	}
	if p.ClientId != "AC123" {
		t.Errorf("provider.ClientId = %q, want AC123 (SID)", p.ClientId)
	}
	if p.ClientSecret != "token" {
		t.Errorf("provider.ClientSecret = %q, want token (AuthToken)", p.ClientSecret)
	}
	if p.AppId != "+15555550100" {
		t.Errorf("provider.AppId = %q, want +15555550100 (FromNumber)", p.AppId)
	}
	if !strings.Contains(p.TemplateCode, "%s") {
		t.Errorf("provider.TemplateCode = %q, want substring %%s", p.TemplateCode)
	}
}

func TestEnvSMSProvider_SandboxReturnsNil(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMSMSProvider, "sandbox")
	EnforceOTPProviderGuard()
	if p := EnvSMSProvider(); p != nil {
		t.Errorf("EnvSMSProvider = %+v, want nil in sandbox mode", p)
	}
}

func TestEnvEmailProvider_ShapeMatchesSendgridAdapter(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMEmailProvider, "sendgrid")
	t.Setenv(envSendgridAPIKey, "SG.xxx")
	t.Setenv(envSendgridFromEmail, "no-reply@example.com")
	t.Setenv(envSendgridFromName, "Example Verification")
	EnforceOTPProviderGuard()

	p := EnvEmailProvider()
	if p == nil {
		t.Fatal("EnvEmailProvider = nil; want non-nil under sendgrid mode")
	}
	if p.Type != "SendGrid" {
		t.Errorf("provider.Type = %q, want SendGrid", p.Type)
	}
	if p.ClientSecret != "SG.xxx" {
		t.Errorf("provider.ClientSecret = %q, want SG.xxx (api key)", p.ClientSecret)
	}
	if p.ClientId2 != "no-reply@example.com" {
		t.Errorf("provider.ClientId2 = %q, want no-reply@example.com (fromAddress)", p.ClientId2)
	}
	if p.ClientSecret2 != "Example Verification" {
		t.Errorf("provider.ClientSecret2 = %q, want Example Verification (fromName)", p.ClientSecret2)
	}
	if p.Category != "Email" {
		t.Errorf("provider.Category = %q, want Email", p.Category)
	}
}

func TestEnvEmailProvider_FromNameDefaults(t *testing.T) {
	defer resetOTPProviderCache()
	t.Setenv(envIAMEmailProvider, "sendgrid")
	t.Setenv(envSendgridAPIKey, "SG.xxx")
	t.Setenv(envSendgridFromEmail, "no-reply@example.com")
	t.Setenv(envSendgridFromName, "")
	EnforceOTPProviderGuard()

	p := EnvEmailProvider()
	if p == nil {
		t.Fatal("EnvEmailProvider = nil")
	}
	if p.ClientSecret2 == "" {
		t.Errorf("fromName default should be non-empty when env unset")
	}
}

// SandboxOTPAllowed must be false when EITHER side is in real-provider mode.
// This is the read-side double-check that refuses sandbox OTP if a
// production env accidentally carries SANDBOX_GLOBAL_OTP.
func TestSandboxOTPAllowed_FalseUnderEitherRealProvider(t *testing.T) {
	cases := []struct {
		smsMode, emailMode string
		want               bool
	}{
		{"sandbox", "sandbox", true},
		{"twilio", "sandbox", false},
		{"sandbox", "sendgrid", false},
		{"twilio", "sendgrid", false},
	}
	for _, c := range cases {
		func() {
			defer resetOTPProviderCache()
			t.Setenv(envIAMSMSProvider, c.smsMode)
			t.Setenv(envIAMEmailProvider, c.emailMode)
			// Wire any creds that the guard needs so we don't panic.
			if c.smsMode == "twilio" {
				t.Setenv(envTwilioAccountSID, "AC")
				t.Setenv(envTwilioAuthToken, "tok")
				t.Setenv(envTwilioFromNumber, "+1")
			}
			if c.emailMode == "sendgrid" {
				t.Setenv(envSendgridAPIKey, "SG.x")
				t.Setenv(envSendgridFromEmail, "no-reply@example.com")
			}
			EnforceOTPProviderGuard()
			if got := SandboxOTPAllowed(); got != c.want {
				t.Errorf("SandboxOTPAllowed [%s/%s] = %v, want %v",
					c.smsMode, c.emailMode, got, c.want)
			}
		}()
	}
}

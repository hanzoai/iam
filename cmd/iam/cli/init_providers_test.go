// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import "testing"

// specByName is a test helper to fetch one spec from supportedProviders.
func specByName(t *testing.T, name string) providerSpec {
	t.Helper()
	for _, s := range supportedProviders {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no supportedProviders spec named %q", name)
	return providerSpec{}
}

// TestSupportedProviders_AdminDefaults locks the canonical admin-default set:
// the five providers every brand inherits, with their canonical Casdoor
// categories/types. A change here is a deliberate product decision.
func TestSupportedProviders_AdminDefaults(t *testing.T) {
	want := map[string]struct {
		category string
		typ      string
	}{
		"provider-github": {"OAuth", "GitHub"},
		"provider-google": {"OAuth", "Google"},
		"provider-sms":    {"SMS", "Twilio SMS"},
		"provider-email":  {"Email", "Default"},
		"provider-web3":   {"Web3", "MetaMask"},
	}
	if len(supportedProviders) != len(want) {
		t.Fatalf("expected %d specs, got %d", len(want), len(supportedProviders))
	}
	for _, s := range supportedProviders {
		w, ok := want[s.Name]
		if !ok {
			t.Errorf("unexpected spec %q", s.Name)
			continue
		}
		if s.Category != w.category {
			t.Errorf("%s category = %q, want %q", s.Name, s.Category, w.category)
		}
		if s.Type != w.typ {
			t.Errorf("%s type = %q, want %q", s.Name, s.Type, w.typ)
		}
		// All admin-default specs are bootstrap-tolerant: a fresh KMS must not
		// hard-fail provisioning.
		if s.RequiredSecret {
			t.Errorf("%s must be bootstrap-tolerant (RequiredSecret=false)", s.Name)
		}
	}
}

// TestBuildProvider_BootstrapToleratesMissingCreds verifies a credentialed
// spec with no env yields ok=false (skip), no error.
func TestBuildProvider_BootstrapToleratesMissingCreds(t *testing.T) {
	t.Setenv("GITHUB_CLIENT_ID", "")
	t.Setenv("GITHUB_CLIENT_SECRET", "")
	_, ok, err := buildProvider("admin", specByName(t, "provider-github"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected skip (ok=false) when GitHub creds are absent")
	}
}

// TestBuildProvider_GithubFromEnv verifies the OAuth credential quadruple maps
// straight through from env.
func TestBuildProvider_GithubFromEnv(t *testing.T) {
	t.Setenv("GITHUB_CLIENT_ID", "gh-id")
	t.Setenv("GITHUB_CLIENT_SECRET", "gh-secret")
	p, ok, err := buildProvider("admin", specByName(t, "provider-github"))
	if err != nil || !ok {
		t.Fatalf("build github: ok=%v err=%v", ok, err)
	}
	if p.Owner != "admin" || p.ClientID != "gh-id" || p.ClientSecret != "gh-secret" {
		t.Errorf("github provider wrong: %+v", p)
	}
	if p.Category != "OAuth" || p.Type != "GitHub" {
		t.Errorf("github category/type wrong: %s/%s", p.Category, p.Type)
	}
}

// TestBuildProvider_TwilioSMS verifies the Twilio SMS binding: clientId=SID,
// clientSecret=Token, AppId=sender number (TWILIO_SENDER).
func TestBuildProvider_TwilioSMS(t *testing.T) {
	t.Setenv("TWILIO_ACCOUNT_SID", "AC123")
	t.Setenv("TWILIO_AUTH_TOKEN", "tok")
	t.Setenv("TWILIO_SENDER", "+19133923684")
	p, ok, err := buildProvider("admin", specByName(t, "provider-sms"))
	if err != nil || !ok {
		t.Fatalf("build sms: ok=%v err=%v", ok, err)
	}
	if p.ClientID != "AC123" || p.ClientSecret != "tok" {
		t.Errorf("twilio creds wrong: id=%q sec=%q", p.ClientID, p.ClientSecret)
	}
	if p.AppId != "+19133923684" {
		t.Errorf("twilio sender (AppId) = %q, want +19133923684", p.AppId)
	}
	if p.Category != "SMS" || p.Type != "Twilio SMS" {
		t.Errorf("sms category/type wrong: %s/%s", p.Category, p.Type)
	}
}

// TestBuildProvider_SMTPEmail verifies the SMTP binding: clientId=user,
// clientSecret=pass, Host/Port the server, Receiver the envelope-from, and the
// default port when SMTP_PORT is unset.
func TestBuildProvider_SMTPEmail(t *testing.T) {
	t.Setenv("SMTP_USER", "apikey")
	t.Setenv("SMTP_PASS", "smtp-pass")
	t.Setenv("SMTP_HOST", "smtp.hanzo.ai")
	t.Setenv("SMTP_FROM", "no-reply@send.hanzo.ai")
	t.Setenv("SMTP_PORT", "") // exercise the default
	p, ok, err := buildProvider("admin", specByName(t, "provider-email"))
	if err != nil || !ok {
		t.Fatalf("build email: ok=%v err=%v", ok, err)
	}
	if p.ClientID != "apikey" || p.ClientSecret != "smtp-pass" {
		t.Errorf("smtp creds wrong: id=%q sec=%q", p.ClientID, p.ClientSecret)
	}
	if p.Host != "smtp.hanzo.ai" || p.Receiver != "no-reply@send.hanzo.ai" {
		t.Errorf("smtp host/from wrong: host=%q from=%q", p.Host, p.Receiver)
	}
	if p.Port != 587 {
		t.Errorf("smtp default port = %d, want 587", p.Port)
	}
	if p.Category != "Email" || p.Type != "Default" {
		t.Errorf("email category/type wrong: %s/%s", p.Category, p.Type)
	}
}

// TestBuildProvider_SMTPPortParse verifies SMTP_PORT is honoured when valid and
// errors when garbage (validate-at-boundary).
func TestBuildProvider_SMTPPortParse(t *testing.T) {
	t.Setenv("SMTP_USER", "u")
	t.Setenv("SMTP_PASS", "p")
	t.Setenv("SMTP_PORT", "465")
	p, ok, err := buildProvider("admin", specByName(t, "provider-email"))
	if err != nil || !ok {
		t.Fatalf("build email: ok=%v err=%v", ok, err)
	}
	if p.Port != 465 {
		t.Errorf("smtp port = %d, want 465", p.Port)
	}

	t.Setenv("SMTP_PORT", "not-a-number")
	if _, _, err := buildProvider("admin", specByName(t, "provider-email")); err == nil {
		t.Error("expected error for non-numeric SMTP_PORT")
	}
}

// TestBuildProvider_Web3AlwaysOn verifies the keyless Web3 provider is always
// upserted (ok=true even with no env) and carries no credentials.
func TestBuildProvider_Web3AlwaysOn(t *testing.T) {
	// No env set at all.
	p, ok, err := buildProvider("admin", specByName(t, "provider-web3"))
	if err != nil || !ok {
		t.Fatalf("web3 must always upsert: ok=%v err=%v", ok, err)
	}
	if p.ClientID != "" || p.ClientSecret != "" {
		t.Errorf("web3 must be keyless, got id=%q sec=%q", p.ClientID, p.ClientSecret)
	}
	if p.Category != "Web3" || p.Type != "MetaMask" {
		t.Errorf("web3 category/type wrong: %s/%s", p.Category, p.Type)
	}
}

// TestAtoiEnv covers the SMTP_PORT helper directly.
func TestAtoiEnv(t *testing.T) {
	t.Setenv("X_PORT", "")
	if n, err := atoiEnv("X_PORT", 25); err != nil || n != 25 {
		t.Errorf("default: got %d, %v; want 25, nil", n, err)
	}
	t.Setenv("X_PORT", "2525")
	if n, err := atoiEnv("X_PORT", 25); err != nil || n != 2525 {
		t.Errorf("parse: got %d, %v; want 2525, nil", n, err)
	}
	t.Setenv("X_PORT", "abc")
	if _, err := atoiEnv("X_PORT", 25); err == nil {
		t.Error("expected error for non-numeric value")
	}
}

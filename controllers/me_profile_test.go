// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build !skipCi

// me_profile_test.go — pure-unit coverage for the validators and the
// User→MeProfile projection. We deliberately avoid spinning up Beego or
// an xorm engine; the routes themselves exercise standard
// RequireSignedInUser + UpdateUser plumbing already covered by
// account.go's session tests.

package controllers

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"

	"github.com/hanzoai/iam/object"
)

func TestValidateDisplayName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty", "", false},
		{"simple", "Alice", true},
		{"with space", "Alice Bob", true},
		{"hyphen-apostrophe-period", "O'Brien-Smith Jr.", true},
		{"unicode letter", "Renée", true},
		{"33 chars", strings.Repeat("a", 33), false},
		{"32 chars", strings.Repeat("a", 32), true},
		{"emoji rejected", "Alice 🎉", false},
		{"sql injection chars", "Robert'); DROP TABLE--", false},
		{"path traversal", "../../etc/passwd", false},
		{"only spaces", "   ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := validateDisplayName(tc.in)
			gotOK := msg == ""
			if gotOK != tc.ok {
				t.Fatalf("validateDisplayName(%q) ok=%v msg=%q; want ok=%v",
					tc.in, gotOK, msg, tc.ok)
			}
		})
	}
}

func TestValidateLanguage(t *testing.T) {
	for _, lang := range []string{"en", "es", "fr", "de", "ja", "zh", "pt"} {
		if msg := validateLanguage(lang); msg != "" {
			t.Errorf("validateLanguage(%q) rejected: %s", lang, msg)
		}
	}
	for _, lang := range []string{"", "xx", "EN", "english", "en-US", "zh-Hans"} {
		if msg := validateLanguage(lang); msg == "" {
			t.Errorf("validateLanguage(%q) accepted but should have rejected", lang)
		}
	}
}

func TestValidateTimezone(t *testing.T) {
	for _, tz := range []string{"UTC", "America/New_York", "Europe/Berlin", "Asia/Tokyo"} {
		if msg := validateTimezone(tz); msg != "" {
			t.Errorf("validateTimezone(%q) rejected: %s", tz, msg)
		}
	}
	for _, tz := range []string{"", "Not/A/Zone", "EST5EDT-foo", "America/Atlantis"} {
		if msg := validateTimezone(tz); msg == "" {
			t.Errorf("validateTimezone(%q) accepted but should have rejected", tz)
		}
	}
}

func TestValidateTheme(t *testing.T) {
	for _, theme := range []string{"system", "light", "dark"} {
		if msg := validateTheme(theme); msg != "" {
			t.Errorf("validateTheme(%q) rejected: %s", theme, msg)
		}
	}
	for _, theme := range []string{"", "Dark", "auto", "high-contrast"} {
		if msg := validateTheme(theme); msg == "" {
			t.Errorf("validateTheme(%q) accepted but should have rejected", theme)
		}
	}
}

func TestValidateCurrency(t *testing.T) {
	for _, c := range []string{"USD", "EUR", "GBP", "JPY", "XYZ"} {
		if msg := validateCurrency(c, "currency_display"); msg != "" {
			t.Errorf("validateCurrency(%q) rejected: %s", c, msg)
		}
	}
	for _, c := range []string{"", "us", "usd", "USDX", "12$", "US D"} {
		if msg := validateCurrency(c, "currency_display"); msg == "" {
			t.Errorf("validateCurrency(%q) accepted but should have rejected", c)
		}
	}
}

func TestUserToMeProfile_DefaultsForNewUser(t *testing.T) {
	u := &object.User{
		Owner:         "liquidity",
		Name:          "alice",
		Id:            "u_abc",
		DisplayName:   "Alice",
		Email:         "alice@example.com",
		EmailVerified: true,
		CreatedTime:   "2026-06-01T00:00:00Z",
	}
	p := userToMeProfile(u)
	if p.UserID != "u_abc" {
		t.Fatalf("UserID: got %q", p.UserID)
	}
	if p.OrgID != "liquidity" {
		t.Fatalf("OrgID: got %q", p.OrgID)
	}
	if p.Timezone != "UTC" {
		t.Fatalf("default timezone: got %q want UTC", p.Timezone)
	}
	if p.Theme != "system" {
		t.Fatalf("default theme: got %q want system", p.Theme)
	}
	if p.CurrencyDisplay != "USD" {
		t.Fatalf("default currency: got %q want USD", p.CurrencyDisplay)
	}
	if p.VerifiedEmail != true {
		t.Fatal("VerifiedEmail should pass through EmailVerified")
	}
	if p.VerifiedPhone != false {
		t.Fatal("VerifiedPhone should be false when no phone stored")
	}
	if p.SecondaryCurrency != "" {
		t.Fatal("SecondaryCurrency should be omitted when unset")
	}
}

func TestUserToMeProfile_PhoneVerifiedDerivedFromPhone(t *testing.T) {
	u := &object.User{Id: "u_x", Phone: "+15551234567"}
	if !userToMeProfile(u).VerifiedPhone {
		t.Fatal("stored phone should imply VerifiedPhone=true (default)")
	}
}

func TestUserToMeProfile_PhoneVerifiedExplicitOverride(t *testing.T) {
	u := &object.User{
		Id:    "u_x",
		Phone: "+15551234567",
		Properties: map[string]string{
			"phoneVerified": "false",
		},
	}
	if userToMeProfile(u).VerifiedPhone {
		t.Fatal("Properties[phoneVerified]=false must override stored phone")
	}
}

func TestUserToMeProfile_PropertiesProjection(t *testing.T) {
	u := &object.User{
		Id:       "u_y",
		Currency: "EUR",
		Properties: map[string]string{
			"timezone":            "Europe/Paris",
			"theme":               "dark",
			"secondaryCurrency":   "USD",
			"lastSigninUserAgent": "Mozilla/5.0",
		},
	}
	p := userToMeProfile(u)
	if p.Timezone != "Europe/Paris" {
		t.Errorf("timezone: %q", p.Timezone)
	}
	if p.Theme != "dark" {
		t.Errorf("theme: %q", p.Theme)
	}
	if p.SecondaryCurrency != "USD" {
		t.Errorf("secondary: %q", p.SecondaryCurrency)
	}
	if p.CurrencyDisplay != "EUR" {
		t.Errorf("currency: %q", p.CurrencyDisplay)
	}
	if p.LastLoginUA != "Mozilla/5.0" {
		t.Errorf("UA: %q", p.LastLoginUA)
	}
}

func TestUserToMeProfile_BalanceCurrencyFallback(t *testing.T) {
	u := &object.User{Id: "u_z", BalanceCurrency: "GBP"}
	if got := userToMeProfile(u).CurrencyDisplay; got != "GBP" {
		t.Fatalf("BalanceCurrency fallback: got %q want GBP", got)
	}
}

func TestSniffAvatarMime_JPEG(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	img.Set(0, 0, color.White)
	buf := &bytes.Buffer{}
	if err := jpeg.Encode(buf, img, nil); err != nil {
		t.Fatalf("encode: %v", err)
	}
	mime, ext, ok := sniffAvatarMime(buf.Bytes())
	if !ok || mime != "image/jpeg" || ext != ".jpg" {
		t.Fatalf("jpeg sniff: mime=%q ext=%q ok=%v", mime, ext, ok)
	}
}

func TestSniffAvatarMime_PNG(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	buf := &bytes.Buffer{}
	if err := png.Encode(buf, img); err != nil {
		t.Fatalf("encode: %v", err)
	}
	mime, ext, ok := sniffAvatarMime(buf.Bytes())
	if !ok || mime != "image/png" || ext != ".png" {
		t.Fatalf("png sniff: mime=%q ext=%q ok=%v", mime, ext, ok)
	}
}

func TestSniffAvatarMime_WebPSig(t *testing.T) {
	// Minimal RIFF/WEBP signature (12 bytes are enough for the sniffer).
	data := []byte("RIFF\x00\x00\x00\x00WEBPextra-bytes")
	mime, ext, ok := sniffAvatarMime(data)
	if !ok || mime != "image/webp" || ext != ".webp" {
		t.Fatalf("webp sniff: mime=%q ext=%q ok=%v", mime, ext, ok)
	}
}

func TestSniffAvatarMime_Rejects(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte(""),
		[]byte("GIF89a..."),                              // GIF — not allowed
		[]byte("<svg xmlns=\"http://www.w3.org/...\"/>"), // SVG — not allowed (XSS surface)
		[]byte("BM..."),                                  // BMP
		[]byte("\x00\x00\x01\x00"),                       // ICO
		[]byte("HTTP/1.1 200 OK\r\n"),                    // arbitrary text
	} {
		if _, _, ok := sniffAvatarMime(data); ok {
			t.Errorf("sniffAvatarMime accepted disallowed payload prefix %q", string(data[:min(len(data), 16)]))
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type captured struct {
	path, org, auth string
	body            sendRequest
}

// spy stands in for cloud's notify surface and records the one request made.
func spy(t *testing.T, status int) (*Client, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.org = r.Header.Get("X-Org-Id")
		got.auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"error","msg":"twilio: 21608 unverified number"}`))
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "tok", "hanzo"), got
}

// A blank address yields NO client, and that nil is the entire delivery switch:
// the composition root binds only a non-nil one, so DeliveryConfigured stays
// false and every screen keeps hiding the methods this process cannot finish.
func TestNoAddressMeansNoClient(t *testing.T) {
	for _, addr := range []string{"", "   "} {
		if c := New(addr, "tok", "hanzo"); c != nil {
			t.Errorf("New(%q) returned a client; an unset address must not look like delivery", addr)
		}
	}
	if New("https://api.hanzo.ai", "", "hanzo") == nil {
		t.Error("a real address must yield a client even with no token")
	}
}

// IAM says "phone", notify says "sms". The translation happens at exactly this
// boundary so neither side has to learn the other's word.
func TestChannelNamesAreTranslatedAtTheBoundary(t *testing.T) {
	for _, tc := range []struct{ channel, wantPath string }{
		{"phone", "/v1/notify/send/sms"},
		{"sms", "/v1/notify/send/sms"},
		{"email", "/v1/notify/send/email"},
	} {
		c, got := spy(t, 200)
		if err := c.Send(context.Background(), "hanzo", tc.channel, "dest", "123456"); err != nil {
			t.Fatalf("Send(%q): %v", tc.channel, err)
		}
		if got.path != tc.wantPath {
			t.Errorf("channel %q posted to %q, want %q", tc.channel, got.path, tc.wantPath)
		}
	}
}

// The tenant must ride the request: notify picks the provider credential by org,
// so a send that named none would be routed through nobody's account — or worse,
// a default one belonging to another tenant.
func TestOrgIsRequiredAndTravels(t *testing.T) {
	c, got := spy(t, 200)
	if err := c.Send(context.Background(), "", "email", "a@b.test", "123456"); err == nil {
		t.Fatal("a send with no org must fail rather than be routed by guesswork")
	}
	if got.path != "" {
		t.Fatal("a send with no org reached the network")
	}

	c, got = spy(t, 200)
	if err := c.Send(context.Background(), "hanzo", "email", "a@b.test", "123456"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got.org != "hanzo" {
		t.Errorf("X-Org-Id = %q, want hanzo", got.org)
	}
	if got.auth != "Bearer tok" {
		t.Errorf("Authorization = %q, want the service token", got.auth)
	}
}

// The code reaches the person, and the message names no brand — one process
// answers for every white-label identity host, so a hardcoded name would be the
// wrong one on most of them.
func TestMessageCarriesTheCodeAndNoBrand(t *testing.T) {
	c, got := spy(t, 200)
	if err := c.Send(context.Background(), "hanzo", "phone", "+14155550134", "246810"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(got.body.Body, "246810") {
		t.Errorf("body %q does not carry the code", got.body.Body)
	}
	if len(got.body.To) != 1 || got.body.To[0] != "+14155550134" {
		t.Errorf("to = %v, want the one destination", got.body.To)
	}
	for _, brand := range []string{"Hanzo", "Lux", "Zoo"} {
		if strings.Contains(got.body.Body, brand) {
			t.Errorf("message names the brand %q; this process serves every identity host", brand)
		}
	}
	// Subject rides email only — an SMS has nowhere to put one.
	if got.body.Subject != "" {
		t.Errorf("sms carried a subject: %q", got.body.Subject)
	}
}

// A refusal from the provider must surface, with enough of the answer to be
// diagnosable — that detail is the difference between "SMS is broken" and
// "this number is unverified on the org's Twilio account".
func TestProviderRefusalSurfaces(t *testing.T) {
	c, _ := spy(t, 400)
	err := c.Send(context.Background(), "hanzo", "phone", "+14155550134", "123456")
	if err == nil {
		t.Fatal("a non-2xx answer must be reported as a failed send")
	}
	if !strings.Contains(err.Error(), "21608") {
		t.Errorf("error %q drops the provider's reason", err)
	}
}

// An unknown channel is refused rather than guessed into one of the two routes.
func TestUnknownChannelIsRefused(t *testing.T) {
	c, got := spy(t, 200)
	if err := c.Send(context.Background(), "hanzo", "carrier-pigeon", "dest", "123456"); err == nil {
		t.Fatal("an unknown channel must not be sent")
	}
	if got.path != "" {
		t.Fatal("an unknown channel reached the network")
	}
}

// A credential is a principal of ONE tenant and notify sends as the principal,
// so a code minted for another org would go out through THIS org's provider --
// delivered, but billed and attributed to the wrong company. Refuse instead.
func TestSendingForAnotherTenantIsRefused(t *testing.T) {
	c, got := spy(t, 200)
	err := c.Send(context.Background(), "lux", "phone", "+14155550134", "123456")
	if err == nil {
		t.Fatal("a send for another tenant must be refused, not routed through this org's provider")
	}
	if !strings.Contains(err.Error(), "lux") || !strings.Contains(err.Error(), "hanzo") {
		t.Errorf("error %q should name both the credential's org and the one asked for", err)
	}
	if got.path != "" {
		t.Fatal("a cross-tenant send reached the network")
	}
}

// An org with no address, or an address with no org, is not delivery. Both must
// yield nil so nothing is bound and the login screens keep hiding code sign-in.
func TestOrgIsPartOfTheDeliveryClaim(t *testing.T) {
	if New("https://api.hanzo.ai", "tok", "") != nil {
		t.Error("an address with no org looked like delivery")
	}
	if New("", "tok", "hanzo") != nil {
		t.Error("an org with no address looked like delivery")
	}
}

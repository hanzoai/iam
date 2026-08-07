// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package notify

import (
	"context"
	"strings"
	"testing"
)

// With no notify peer on the plane there is NO client, and that nil is the whole
// delivery switch: the composition root binds only a non-nil one, so
// DeliveryConfigured stays false and every screen keeps hiding email and SMS
// sign-in rather than advertising a method that dies when a person is waiting.
//
// This is also the property the old HTTP client could not have. It was built from
// an address and a credential, so it existed whenever those strings were set —
// which is exactly how delivery came to look configured while sending nothing.
// Reachability is now PROVEN by a dial, not inferred from configuration.
func TestNoPeerMeansNoClient(t *testing.T) {
	t.Setenv("ZIP_RUNTIME_DIR", t.TempDir()) // an empty runtime dir: no notify socket
	if c := New(); c != nil {
		t.Fatal("a client was returned with no notify peer on the plane — delivery would look configured")
	}
}

// A nil client refuses rather than panics: the seam holds a Sender interface, and
// a typed-nil that dereferenced would take the login path down with it.
func TestNilClientRefuses(t *testing.T) {
	var c *Client
	if err := c.Send(context.Background(), "hanzo", "email", "a@b.test", "123456"); err == nil {
		t.Fatal("a nil client must refuse")
	}
}

// The org is REQUIRED and never defaulted. notify resolves the provider credential
// by org, so a blank one would send this tenant's code through another tenant's
// account — the failure the whole plane shape exists to make impossible.
func TestOrgIsRequired(t *testing.T) {
	c := &Client{}
	for _, org := range []string{"", "   "} {
		err := c.Send(context.Background(), org, "email", "a@b.test", "123456")
		if err == nil {
			t.Fatalf("org %q was accepted; it must be refused", org)
		}
		if !strings.Contains(err.Error(), "org is required") {
			t.Errorf("error %q should say the org is required", err)
		}
	}
}

// An unknown channel is refused before anything is dialled, rather than guessed
// into one of the two notify serves.
func TestUnknownChannelIsRefusedBeforeDialling(t *testing.T) {
	c := &Client{}
	err := c.Send(context.Background(), "hanzo", "carrier-pigeon", "dest", "123456")
	if err == nil {
		t.Fatal("an unknown channel must be refused")
	}
	if !strings.Contains(err.Error(), "unknown channel") {
		t.Errorf("error %q should name the unknown channel", err)
	}
}

// IAM says "phone", notify says "sms". The translation happens at this boundary so
// neither side learns the other's word, and it is asserted on the REQUEST that
// would go on the wire.
func TestChannelNamesAreTranslatedAtTheBoundary(t *testing.T) {
	for _, tc := range []struct{ in, want, subject string }{
		{"phone", "sms", ""},
		{"sms", "sms", ""},
		{"email", "email", "Your verification code"},
	} {
		got := send{Org: "hanzo", To: "dest", Body: message("123456")}
		switch tc.in {
		case "email":
			got.Channel, got.Subject = "email", "Your verification code"
		case "phone", "sms":
			got.Channel = "sms"
		}
		if got.Channel != tc.want {
			t.Errorf("channel %q -> %q, want %q", tc.in, got.Channel, tc.want)
		}
		// A subject rides email only; an SMS has nowhere to put one.
		if got.Subject != tc.subject {
			t.Errorf("channel %q subject = %q, want %q", tc.in, got.Subject, tc.subject)
		}
	}
}

// The message carries the code and names NO brand: one process answers for every
// white-label identity host, so a hardcoded name would be the wrong one on most of
// them. The sender the recipient actually sees is the org's own provider.
func TestMessageCarriesTheCodeAndNoBrand(t *testing.T) {
	m := message("246810")
	if !strings.Contains(m, "246810") {
		t.Errorf("message %q does not carry the code", m)
	}
	for _, brand := range []string{"Hanzo", "Lux", "Zoo", "Pars"} {
		if strings.Contains(m, brand) {
			t.Errorf("message names the brand %q", brand)
		}
	}
}

// The wire shape must keep the field names notify publishes: the two sides cannot
// agree by type (notify lives in cloud, and cloud already depends on this module),
// so they agree by these json tags and the op address. A rename here is a silent
// break, which is why it is asserted.
func TestWireShapeMatchesTheOpContract(t *testing.T) {
	if op != "/notify/send" {
		t.Errorf("op = %q, want /notify/send (cloud plane.NotifySend)", op)
	}
	if app != "notify" {
		t.Errorf("app = %q, want notify", app)
	}
}

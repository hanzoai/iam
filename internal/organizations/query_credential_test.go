// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

// An organization's credentials are body-only.
//
// UpdateOrganizationInput embeds schema.Organization ANONYMOUSLY, and zip's URL
// binder walks promoted fields exactly as the JSON decoder does — so every scalar
// the record carries is reachable from the URL, master password included. The
// query binds after the body, so it does not offer a second source: it overrides
// the one the caller sent.

import (
	"strings"
	"testing"
)

// A query string cannot choose an organization's master password. The body sends
// the real one; the URL asks for another; the row keeps the body's.
func TestMember_credentialsComeFromTheBodyNotTheQuery(t *testing.T) {
	h := newHarness(t)

	const body = `{"owner":"admin","name":"hanzo","displayName":"Hanzo",` +
		`"masterPassword":"hunter2","defaultPassword":"welcome","masterVerificationCode":"123456"}`
	target := memberPath + "hanzo?masterPassword=stranger&defaultPassword=stranger&masterVerificationCode=999999"

	status, got := h.call(t, "PUT", target, "admin/root", body)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, got)
	}

	org := h.stored(t, "hanzo")
	for _, c := range []struct{ field, got, want string }{
		{"masterPassword", org.MasterPassword, "hunter2"},
		{"defaultPassword", org.DefaultPassword, "welcome"},
		{"masterVerificationCode", org.MasterVerificationCode, "123456"},
	} {
		if c.got != c.want {
			t.Errorf("%s bound from the query: stored %q, want the body's %q", c.field, c.got, c.want)
		}
		if strings.Contains(c.got, "stranger") || c.got == "999999" {
			t.Errorf("%s took the value the URL carried", c.field)
		}
	}
}

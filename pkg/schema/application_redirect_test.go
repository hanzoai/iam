// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "testing"

// The registration the provisioner actually writes for a `cli` app
// (internal/provision, TypeCLI) plus a representative browser client.
func cliApp() *Application {
	return &Application{RedirectUris: []string{
		"http://127.0.0.1/callback",
		"http://localhost/callback",
		"https://cloud.hanzo.ai/auth/callback",
	}}
}

func TestLoopbackEphemeralPortIsAccepted(t *testing.T) {
	a := cliApp()
	// The exact shape hanzo/cli sends after binding 127.0.0.1:0. This is the
	// case that used to 400 and hang the CLI on accept().
	for _, uri := range []string{
		"http://127.0.0.1:51234/callback",
		"http://127.0.0.1:1/callback",
		"http://127.0.0.1:65535/callback",
		"http://127.0.0.1/callback", // portless still matches exactly
	} {
		if !a.IsRedirectUriValid(uri) {
			t.Errorf("IsRedirectUriValid(%q) = false, want true", uri)
		}
	}
}

func TestLoopbackIPv6EphemeralPortIsAccepted(t *testing.T) {
	a := &Application{RedirectUris: []string{"http://[::1]/callback"}}
	if !a.IsRedirectUriValid("http://[::1]:51234/callback") {
		t.Error("IPv6 loopback with an ephemeral port must match its portless registration")
	}
}

// The port is the ONLY axis that may vary. Everything else stays exact.
func TestLoopbackMatchIsPortOnly(t *testing.T) {
	a := cliApp()
	for _, uri := range []string{
		"http://127.0.0.1:51234/other",         // different path
		"http://127.0.0.1:51234/callback?x=1",  // added query
		"http://127.0.0.1:51234/callback#frag", // added fragment
		"https://127.0.0.1:51234/callback",     // https is not a loopback listener
		"http://127.0.0.2:51234/callback",      // different loopback-range IP
		"http://127.0.0.1.evil.com/callback",   // suffix attack on the host
		"http://evil.com/callback",             // unrelated host
		"http://[::2]:51234/callback",          // not ::1
	} {
		if a.IsRedirectUriValid(uri) {
			t.Errorf("IsRedirectUriValid(%q) = true, want false", uri)
		}
	}
}

// localhost is registered but deliberately does NOT get the port wildcard
// (RFC 8252 §8.3 — it resolves through DNS, so it is not provably local).
func TestLocalhostKeepsExactMatchOnly(t *testing.T) {
	a := cliApp()
	if !a.IsRedirectUriValid("http://localhost/callback") {
		t.Error("registered localhost URI must still match exactly")
	}
	if a.IsRedirectUriValid("http://localhost:51234/callback") {
		t.Error("localhost must not gain the loopback port wildcard")
	}
}

// A non-loopback registration must never be widened by this change.
func TestRemoteRegistrationUnaffected(t *testing.T) {
	a := cliApp()
	if !a.IsRedirectUriValid("https://cloud.hanzo.ai/auth/callback") {
		t.Error("exact remote match regressed")
	}
	for _, uri := range []string{
		"https://cloud.hanzo.ai:8443/auth/callback", // port must NOT be ignored off-loopback
		"https://cloud.hanzo.ai/auth/callback/../x",
		"",
	} {
		if a.IsRedirectUriValid(uri) {
			t.Errorf("IsRedirectUriValid(%q) = true, want false", uri)
		}
	}
}

// An app that registered a SPECIFIC loopback port still accepts any port: the
// RFC allows any port at request time regardless of what was registered.
func TestRegisteredLoopbackPortStillAcceptsAnyPort(t *testing.T) {
	a := &Application{RedirectUris: []string{"http://127.0.0.1:1455/auth/callback"}}
	if !a.IsRedirectUriValid("http://127.0.0.1:51234/auth/callback") {
		t.Error("a registered loopback port must not pin the runtime port")
	}
	if a.IsRedirectUriValid("http://127.0.0.1:51234/different") {
		t.Error("path must still match")
	}
}

func TestEmptyRegistrationsRejectEverything(t *testing.T) {
	a := &Application{RedirectUris: []string{"", "  "}}
	if a.IsRedirectUriValid("http://127.0.0.1:51234/callback") {
		t.Error("blank registrations must never match")
	}
}

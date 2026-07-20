// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package social_test

import (
	"strings"
	"testing"
)

// Every provider publishes whether it has verified an address, and v1 parses
// all three signals and drops all three (idp/google.go:124, github.go:325-347,
// gitlab.go:186). Verified is the ONE bit the link law turns on, so each
// connector's mapping is asserted here end to end: the bit lands on the account
// the sign-up creates, which is exactly what a later sign-in may link by.

func TestVerifiedPerProvider(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   string
		user   map[string]any
		emails any
		email  string
		want   bool
	}{{
		name: "google verified_email true",
		kind: "Google",
		user: map[string]any{"id": "1", "email": "z@hanzo.ai", "verified_email": true, "name": "Z"},
		want: true, email: "z@hanzo.ai",
	}, {
		name: "google verified_email false",
		kind: "Google",
		user: map[string]any{"id": "1", "email": "z@hanzo.ai", "verified_email": false, "name": "Z"},
		want: false, email: "z@hanzo.ai",
	}, {
		name: "google verified_email absent",
		kind: "Google",
		user: map[string]any{"id": "1", "email": "z@hanzo.ai", "name": "Z"},
		want: false, email: "z@hanzo.ai",
	}, {
		// GitHub publishes a profile email only once it is verified.
		name: "github public profile email",
		kind: "GitHub",
		user: map[string]any{"id": 1, "login": "zeekay", "email": "z@hanzo.ai"},
		want: true, email: "z@hanzo.ai",
	}, {
		name:   "github verified primary address",
		kind:   "GitHub",
		user:   map[string]any{"id": 1, "login": "zeekay", "email": ""},
		emails: []map[string]any{{"email": "z@hanzo.ai", "primary": true, "verified": true}},
		want:   true, email: "z@hanzo.ai",
	}, {
		// Only the unverified address is on file: it is not a link key, and it
		// is not the account's address either.
		name:   "github unverified address only",
		kind:   "GitHub",
		user:   map[string]any{"id": 1, "login": "zeekay", "email": ""},
		emails: []map[string]any{{"email": "z@hanzo.ai", "primary": true, "verified": false}},
		want:   false, email: "1+zeekay@users.noreply.github.com",
	}, {
		// The noreply alias is an identifier, not a mailbox.
		name:   "github noreply fallback",
		kind:   "GitHub",
		user:   map[string]any{"id": 1, "login": "zeekay", "email": ""},
		emails: nil,
		want:   false, email: "1+zeekay@users.noreply.github.com",
	}, {
		name: "github skips the noreply alias when a real address is verified",
		kind: "GitHub",
		user: map[string]any{"id": 1, "login": "zeekay", "email": ""},
		emails: []map[string]any{
			{"email": "1+zeekay@users.noreply.github.com", "primary": true, "verified": true},
			{"email": "z@hanzo.ai", "primary": false, "verified": true},
		},
		want: true, email: "z@hanzo.ai",
	}, {
		name: "gitlab confirmed_at set",
		kind: "GitLab",
		user: map[string]any{"id": 1, "username": "zeekay", "email": "z@hanzo.ai",
			"confirmed_at": "2026-01-01T00:00:00Z"},
		want: true, email: "z@hanzo.ai",
	}, {
		name: "gitlab confirmed_at null",
		kind: "GitLab",
		user: map[string]any{"id": 1, "username": "zeekay", "email": "z@hanzo.ai",
			"confirmed_at": nil},
		want: false, email: "z@hanzo.ai",
	}, {
		name: "gitlab confirmed_at absent",
		kind: "GitLab",
		user: map[string]any{"id": 1, "username": "zeekay", "email": "z@hanzo.ai"},
		want: false, email: "z@hanzo.ai",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			up := newUpstream(t)
			seedAll(t, db, up, seed{kind: tc.kind, signup: true, canSignIn: true, canSignUp: true})
			up.user, up.emails = tc.user, tc.emails

			resp, _ := signin(t, app, "provider-"+strings.ToLower(tc.kind))
			if issued(t, resp) == "" {
				t.Fatal("no code was issued")
			}
			// Google publishes no handle, so the account is named by address —
			// v1's choice, kept.
			name := "zeekay"
			if tc.kind == "Google" {
				name = tc.email
			}
			u := getUser(t, db, "hanzo", name)
			if u == nil {
				t.Fatalf("no account %q was created", name)
			}
			if u.EmailVerified != tc.want {
				t.Fatalf("EmailVerified: want %v, got %v", tc.want, u.EmailVerified)
			}
			if u.Email != tc.email {
				t.Fatalf("Email: want %q, got %q", tc.email, u.Email)
			}
		})
	}
}

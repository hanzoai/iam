// Copyright © 2026 Hanzo AI. MIT License.

package object

import (
	"reflect"
	"testing"
)

// TestTokenAudience pins the `aud` decision that lets a confidential client
// (hanzo-console) mint a user token whose audience a fixed resource-server
// allowlist (commerce IAM_ACCEPTED_AUDIENCES) accepts — the core of
// GetUserTokenForAudience / IssueUserToken. It is the audience-selection
// contract, decomplected from JWT assembly so it needs no DB/cert.
func TestTokenAudience(t *testing.T) {
	const clientID = "app-console-client-id"
	const owner = "acme"

	cases := []struct {
		name     string
		resource string
		shared   bool
		want     []string
	}{
		{
			// The load-bearing new path: an explicit resource forces aud to the
			// named resource server, REGARDLESS of which app minted the token —
			// so commerce's "hanzo-console" allowlist entry matches even though
			// the minting app's clientId is something else entirely.
			name:     "explicit resource wins over clientId",
			resource: "hanzo-console",
			shared:   false,
			want:     []string{"hanzo-console"},
		},
		{
			// Explicit resource wins even for a shared app (no per-org suffix):
			// the caller has named the audience deliberately.
			name:     "explicit resource wins over shared per-org default",
			resource: "hanzo-console",
			shared:   true,
			want:     []string{"hanzo-console"},
		},
		{
			// Default, unchanged for every existing login/OAuth flow: aud is the
			// minting app's clientId.
			name:     "no resource, non-shared app -> clientId",
			resource: "",
			shared:   false,
			want:     []string{clientID},
		},
		{
			// Shared app, no resource: per-org audience keeps a shared app's
			// tokens org-scoped (unchanged legacy behavior).
			name:     "no resource, shared app -> per-org audience",
			resource: "",
			shared:   true,
			want:     []string{clientID + "-org-" + owner},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := &Application{ClientId: clientID, IsShared: tc.shared}
			got := tokenAudience(tc.resource, app, owner)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("tokenAudience(%q, shared=%v, owner=%q) = %v, want %v",
					tc.resource, tc.shared, owner, got, tc.want)
			}
		})
	}
}

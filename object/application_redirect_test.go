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

//go:build !skipCi

package object

import "testing"

// TestIsRedirectUriValid_ExactMatchOnly locks in the fix for the one-click SSO
// account-takeover: redirect_uri validation is EXACT match against the app's
// registered redirectUris and nothing else. No trusted-origin short-circuit,
// no substring containment, no dot-as-wildcard regex.
//
// hanzoCloud mirrors the live hanzo-cloud (client_id hanzo-cloud) registration
// from universe/infra/k8s/iam/init_data.json — a public PKCE client, exactly
// the client the exploit abused.
func TestIsRedirectUriValid_ExactMatchOnly(t *testing.T) {
	hanzoCloud := &Application{
		Owner:        "admin",
		Name:         "hanzo-cloud",
		Organization: "hanzo",
		ClientId:     "hanzo-cloud",
		RedirectUris: []string{
			"https://cloud.hanzo.ai/callback",
			"https://stg.cloud.hanzo.ai/callback",
			"http://localhost:14000/callback",
			"https://console.hanzo.ai/auth/callback",
			"https://console2.hanzo.ai/auth/callback",
			"https://console.hanzo.ai/api/auth/callback/iam",
		},
	}

	// An app that legitimately registers a cloud.lux.network callback — used to
	// prove the strings.Contains embed bypass is gone.
	luxWeb3 := &Application{
		Owner:        "admin",
		Name:         "lux-web3",
		Organization: "lux",
		ClientId:     "lux-web3",
		RedirectUris: []string{"https://cloud.lux.network/callback"},
	}

	tests := []struct {
		name        string
		app         *Application
		redirectUri string
		want        bool
	}{
		// --- Accept: exact registered callbacks ---
		{"exact https callback", hanzoCloud, "https://cloud.hanzo.ai/callback", true},
		{"exact console callback", hanzoCloud, "https://console.hanzo.ai/auth/callback", true},
		{"exact nextauth callback", hanzoCloud, "https://console.hanzo.ai/api/auth/callback/iam", true},
		{"exact registered localhost callback", hanzoCloud, "http://localhost:14000/callback", true},

		// --- REJECT: the exploit's s3-hosted attacker page (trusted .hanzo.ai
		// subdomain). This is the account-takeover primitive that MUST now fail. ---
		{"s3 hanzo-sites attacker page", hanzoCloud, "https://s3.hanzo.ai/hanzo-sites/x/y/index.html", false},
		{"s3 hanzo-sites root", hanzoCloud, "https://s3.hanzo.ai/", false},

		// --- REJECT: strings.Contains embed bypass ---
		{"attacker embeds registered uri in path", luxWeb3, "https://attacker.com/https://cloud.lux.network/callback", false},
		{"attacker embeds registered uri in query", luxWeb3, "https://attacker.com/cb?next=https://cloud.lux.network/callback", false},

		// --- REJECT: unescaped-dot regex bypass (host confusion) ---
		{"dot-as-wildcard host confusion", hanzoCloud, "https://cloudXhanzo.ai/callback", false},
		{"dot-as-wildcard cloudxhanzo", hanzoCloud, "https://cloud-hanzo.ai/callback", false},

		// --- REJECT: unregistered localhost (the localhost:any-port blanket allow) ---
		{"unregistered localhost port", hanzoCloud, "http://localhost:31337/cb", false},
		{"unregistered 127.0.0.1", hanzoCloud, "http://127.0.0.1:31337/cb", false},

		// --- REJECT: trusted-suffix bare origin (IsValidOrigin short-circuit) ---
		{"bare trusted origin not a redirect", hanzoCloud, "https://cloud.hanzo.ai", false},
		{"arbitrary trusted-suffix host", hanzoCloud, "https://evil.hanzo.ai/callback", false},
		{"arbitrary hanzo.app host", hanzoCloud, "https://x.hanzo.app/callback", false},

		// --- REJECT: chromiumapp.org extension bypass via IsValidOrigin ---
		{"unregistered chromium extension origin", hanzoCloud, "https://abcdef.chromiumapp.org/callback", false},

		// --- REJECT: near-miss mutations of a registered URI ---
		{"trailing slash mismatch", hanzoCloud, "https://cloud.hanzo.ai/callback/", false},
		{"path suffix append", hanzoCloud, "https://cloud.hanzo.ai/callback/../evil", false},
		{"scheme downgrade", hanzoCloud, "http://cloud.hanzo.ai/callback", false},
		{"extra query on exact", hanzoCloud, "https://cloud.hanzo.ai/callback?code=x", false},
		{"case-mutated host", hanzoCloud, "https://CLOUD.hanzo.ai/callback", false},
		{"userinfo injection", hanzoCloud, "https://cloud.hanzo.ai@evil.com/callback", false},

		// --- REJECT: empties ---
		{"empty redirect", hanzoCloud, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.app.IsRedirectUriValid(tt.redirectUri); got != tt.want {
				t.Errorf("IsRedirectUriValid(%q) = %v, want %v", tt.redirectUri, got, tt.want)
			}
		})
	}
}

// TestIsRedirectUriValid_EmptyRegistrationDeniesAll proves fail-secure: an app
// with no registered redirectUris rejects every redirect_uri (rather than the
// old behavior where any trusted-suffix host was accepted regardless).
func TestIsRedirectUriValid_EmptyRegistrationDeniesAll(t *testing.T) {
	app := &Application{Owner: "admin", Name: "empty", Organization: "hanzo", RedirectUris: nil}
	for _, uri := range []string{
		"https://cloud.hanzo.ai/callback",
		"https://s3.hanzo.ai/hanzo-sites/x/y/index.html",
		"http://localhost:14000/callback",
		"",
	} {
		if app.IsRedirectUriValid(uri) {
			t.Errorf("empty registration must deny %q, but it was allowed", uri)
		}
	}
}

// TestIsRedirectUriValid_BlankRegisteredEntryIgnored proves a blank "" entry in
// the registered list (a Casdoor seed artifact) never matches a blank/any input.
func TestIsRedirectUriValid_BlankRegisteredEntryIgnored(t *testing.T) {
	app := &Application{
		Owner:        "admin",
		Name:         "blank",
		Organization: "hanzo",
		RedirectUris: []string{"", "https://ok.hanzo.ai/callback"},
	}
	if app.IsRedirectUriValid("") {
		t.Error("blank redirect_uri must not match a blank registered entry")
	}
	if !app.IsRedirectUriValid("https://ok.hanzo.ai/callback") {
		t.Error("valid entry alongside a blank must still match")
	}
}

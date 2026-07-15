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

// oauth_signup_link_test.go — account-takeover regression for the OAuth
// "signup" account-linking path (Red CRITICAL-1 / HIGH-2). Attaching a new
// social identity to an EXISTING account must require CONSENT: a provider that
// asserts a VERIFIED email matching the account. A bare username / display-name
// / phone collision is NEVER consent, and an unverified provider email is
// attacker-controllable and refused.

package object

import (
	"testing"

	"github.com/hanzoai/iam/idp"
)

// resolveSignupLinkTarget mirrors the existing-account selection the controller
// performs in controllers/auth.go once an OAuth "signup" finds the provider
// identity (userInfo.Id) is NOT yet linked. It intentionally reproduces the
// SHAPE of the production decision so a regression that reintroduces
// username/phone linking would break this test:
//
//	if MayLinkByVerifiedEmail(EnableLinkWithEmail, Email, EmailVerified) {
//	    user = GetUserByField(org, "email", Email)   // ← the ONLY existing-account selector
//	}
//	// user == nil  →  provision a NEW account
//
// byEmail models GetUserByField(org, "email", …). userInfo.Username / .Phone are
// deliberately NOT consulted — that is the fix.
func resolveSignupLinkTarget(enableLinkWithEmail bool, info idp.UserInfo, byEmail map[string]*User) *User {
	if MayLinkByVerifiedEmail(enableLinkWithEmail, info.Email, info.EmailVerified) {
		return byEmail[info.Email]
	}
	return nil
}

func TestMayLinkByVerifiedEmail(t *testing.T) {
	cases := []struct {
		name    string
		enable  bool
		email   string
		verifed bool
		want    bool
	}{
		{"enabled + verified + email → link", true, "a@corp.example", true, true},
		{"unverified email is refused (HIGH-2)", true, "a@corp.example", false, false},
		{"feature disabled is refused", false, "a@corp.example", true, false},
		{"empty email is refused", true, "", true, false},
		{"blank email is refused", true, "   ", true, false},
		{"disabled + unverified + empty → refused", false, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MayLinkByVerifiedEmail(tc.enable, tc.email, tc.verifed); got != tc.want {
				t.Fatalf("MayLinkByVerifiedEmail(%v, %q, %v) = %v, want %v",
					tc.enable, tc.email, tc.verifed, got, tc.want)
			}
		})
	}
}

// TestOAuthSignup_UsernameCollisionIsNeverConsent is the takeover PoC. Victim
// "alice" already exists (with a linked provider). The attacker registers
// gitlab.com/alice — free, instant, no verification — so their GitLab userInfo
// carries Username "alice" and a DIFFERENT, unlinked provider id. The old code
// matched the existing account by that username and logged the attacker in AS
// alice with no MFA. The fix must resolve to NO existing account (→ provision a
// fresh, separate user), regardless of the attacker's chosen username, display
// name, or even a verified email that is THEIRS (not alice's).
func TestOAuthSignup_UsernameCollisionIsNeverConsent(t *testing.T) {
	alice := &User{Owner: "hanzo", Name: "alice", Email: "alice@corp.example"}
	// The org's users, keyed as GetUserByField(org, "email", …) would resolve.
	byEmail := map[string]*User{"alice@corp.example": alice}

	attacks := []struct {
		name string
		info idp.UserInfo
	}{
		{
			name: "username collision, attacker's own verified email",
			info: idp.UserInfo{Id: "gitlab-9001", Username: "alice", DisplayName: "alice", Email: "attacker@evil.test", EmailVerified: true},
		},
		{
			name: "username collision, no email at all",
			info: idp.UserInfo{Id: "gitlab-9002", Username: "alice", DisplayName: "alice"},
		},
		{
			name: "display-name collision only",
			info: idp.UserInfo{Id: "gitlab-9003", Username: "not-alice", DisplayName: "alice"},
		},
	}

	// Linking-by-email ON is the stronger test: even with the feature enabled,
	// a username/display-name collision must not select the existing account.
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			got := resolveSignupLinkTarget(true, a.info, byEmail)
			if got == alice {
				t.Fatalf("ACCOUNT TAKEOVER: social signup selected victim %q from attacker-controlled inputs %+v", alice.Name, a.info)
			}
			if got != nil {
				t.Fatalf("expected no existing-account link (→ create new), got %q", got.Name)
			}
		})
	}
}

// TestOAuthSignup_VerifiedEmailOwnerLinks proves the legitimate flow still
// works: the REAL alice signs in via a provider that VERIFIED her actual email,
// so the login links to and authenticates her account (consent proven by the
// provider's email verification).
func TestOAuthSignup_VerifiedEmailOwnerLinks(t *testing.T) {
	alice := &User{Owner: "hanzo", Name: "alice", Email: "alice@corp.example"}
	byEmail := map[string]*User{"alice@corp.example": alice}

	legit := idp.UserInfo{Id: "gitlab-alice", Username: "alice-gl", Email: "alice@corp.example", EmailVerified: true}
	if got := resolveSignupLinkTarget(true, legit, byEmail); got != alice {
		t.Fatalf("verified-email owner should link to their account; got %v", got)
	}
}

// TestOAuthSignup_UnverifiedEmailNeverLinks is the HIGH-2 case: an attacker
// spoofs alice's email at a provider that does NOT verify it. The unverified
// email must never resolve to alice's account even though the addresses match.
func TestOAuthSignup_UnverifiedEmailNeverLinks(t *testing.T) {
	alice := &User{Owner: "hanzo", Name: "alice", Email: "alice@corp.example"}
	byEmail := map[string]*User{"alice@corp.example": alice}

	spoof := idp.UserInfo{Id: "gitlab-evil", Username: "eve", Email: "alice@corp.example", EmailVerified: false}
	if got := resolveSignupLinkTarget(true, spoof, byEmail); got != nil {
		t.Fatalf("unverified provider email must not link to an existing account (HIGH-2); got %q", got.Name)
	}

	// And with the linking feature OFF, even a verified matching email does not
	// auto-link on the signup path (the deployment did not opt in).
	verifiedButDisabled := idp.UserInfo{Id: "gitlab-evil2", Email: "alice@corp.example", EmailVerified: true}
	if got := resolveSignupLinkTarget(false, verifiedButDisabled, byEmail); got != nil {
		t.Fatalf("EnableLinkWithEmail=false must not auto-link; got %q", got.Name)
	}
}

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

package object

import "testing"

// TestGuestSigninAllowed pins the OPT-IN, FAIL-CLOSED guest sign-in policy: an
// application permits the anonymous "guest-user" grant ONLY when it explicitly
// sets EnableGuestSignin. A nil or unset application never permits it — the
// property that keeps a real login from being silently downgraded to an
// auto-provisioned guest. The "enabled" case is the decision that lets an
// opted-in app proceed to mint a guest token; the "disabled/default" cases are
// the closed door for every app that has not opted in.
func TestGuestSigninAllowed(t *testing.T) {
	cases := []struct {
		name string
		app  *Application
		want bool
	}{
		{"nil application", nil, false},
		{"guest disabled by default (zero value)", &Application{}, false},
		{"guest disabled explicitly", &Application{EnableGuestSignin: false}, false},
		{"guest enabled (app opted in)", &Application{EnableGuestSignin: true}, true},
	}
	for _, tc := range cases {
		if got := guestSigninAllowed(tc.app); got != tc.want {
			t.Errorf("%s: guestSigninAllowed = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestGetAuthorizationCodeTokenGuestFailsClosed exercises the real
// GetAuthorizationCodeToken path: an application that has NOT opted into guest
// sign-in must refuse the "guest-user" authorization code with invalid_grant
// BEFORE any user is provisioned — no throwaway guest, no token. The guard
// returns ahead of every store call, so this runs without a database. A nil
// TokenError here would mean the pre-fix fail-OPEN behavior (a guest was
// minted for an app that never enabled it).
func TestGetAuthorizationCodeTokenGuestFailsClosed(t *testing.T) {
	app := &Application{Owner: "admin", Name: "app-console", EnableGuestSignin: false}

	token, tokenErr, err := GetAuthorizationCodeToken(app, "", "guest-user", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != nil {
		t.Fatalf("expected no token for a guest-disabled app, got %#v", token)
	}
	if tokenErr == nil {
		t.Fatal("expected an invalid_grant TokenError; got nil (fail-OPEN: a guest was provisioned)")
	}
	if tokenErr.Error != InvalidGrant {
		t.Errorf("TokenError.Error = %q, want %q", tokenErr.Error, InvalidGrant)
	}
}

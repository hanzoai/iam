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

package routers

import (
	"testing"

	"github.com/hanzoai/iam/object"
)

// confidentialClientSubject is the ONE canonical CC->subject rule shared by
// AutoSigninFilter (session seed, runs first) and getUsernameFromBearerToken
// (ApiFilter). These cases pin the behavior that both transports MUST agree on
// so the SA-keystone app caller is never silently pinned to <org>/<app>.
func TestConfidentialClientSubject(t *testing.T) {
	adminApp := &object.Application{Owner: "admin", Name: "hanzo-console", Organization: "hanzo"}

	// Genuine client_credentials token for an admin-owned platform app ->
	// canonical app/<name>. This is the exact hanzo-console CC token shape.
	ccClaims := &object.Claims{User: &object.User{Type: "application", Name: "hanzo-console", Owner: "hanzo"}}
	if sub, isCC := confidentialClientSubject(ccClaims, adminApp); !isCC || sub != "app/hanzo-console" {
		t.Fatalf("CC admin-owned: got (%q,%v), want (\"app/hanzo-console\", true)", sub, isCC)
	}

	// Human-user token (Type != application) -> NOT a confidential client, so the
	// caller keeps its <owner>/<name> resolution. Guarantees human Bearer flows
	// are byte-identical after the fix.
	humanClaims := &object.Claims{User: &object.User{Type: "normal-user", Name: "z", Owner: "hanzo"}}
	if sub, isCC := confidentialClientSubject(humanClaims, adminApp); isCC || sub != "" {
		t.Fatalf("human user: got (%q,%v), want (\"\", false)", sub, isCC)
	}

	// Forgery shape: Type=application but name != app.name -> not a genuine CC
	// token (the strongest discriminator field), keep human resolution.
	forgery := &object.Claims{User: &object.User{Type: "application", Name: "not-the-app", Owner: "hanzo"}}
	if sub, isCC := confidentialClientSubject(forgery, adminApp); isCC || sub != "" {
		t.Fatalf("name-mismatch forgery: got (%q,%v), want (\"\", false)", sub, isCC)
	}

	// A CC token carrying a Provider (password/OIDC grant shape) is not a
	// confidential-client token.
	withProvider := &object.Claims{User: &object.User{Type: "application", Name: "hanzo-console", Owner: "hanzo"}, Provider: "github"}
	if sub, isCC := confidentialClientSubject(withProvider, adminApp); isCC || sub != "" {
		t.Fatalf("provider-set: got (%q,%v), want (\"\", false)", sub, isCC)
	}
}

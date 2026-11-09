// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package applications

import (
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// signinUrl is an address the authorize endpoint redirects to, so what is stored is
// an https URL or nothing. A tenant's application once stored `javascript:alert(1)//`
// and any URL at all, and the issuer redirected to it.
func TestSigninUrl_OnlyAnHttpsUrlIsStoredOnCreateAndUpdate(t *testing.T) {
	db := memDB(t)
	ctx := asSuper()
	seedConfidential(t, db, "acme-web", "s3cret")

	for _, bad := range []string{"javascript:alert(1)//", "http://evil.example/login", "//evil.example/login", "https://user:pw@evil.example/", "data:text/html,x", "evil.example"} {
		in := &schema.Application{Owner: "admin", Name: "acme-new", ClientId: "acme-new", Organization: "acme", ClientSecret: "x", SigninUrl: bad}
		if _, err := Create(db)(ctx, in); err == nil || !strings.Contains(err.Error(), "signinUrl") {
			t.Errorf("create of signinUrl %q: %v, want the signinUrl refusal", bad, err)
		}
		up := &schema.Application{Owner: "admin", Name: "acme-web", ClientId: "acme-web", Organization: "hanzo", SigninUrl: bad}
		if _, err := Update(db)(ctx, up); err == nil || !strings.Contains(err.Error(), "signinUrl") {
			t.Errorf("update of signinUrl %q: %v, want the signinUrl refusal", bad, err)
		}
	}
	for _, good := range []string{"", "https://hanzo.ai/login"} {
		up := &schema.Application{Owner: "admin", Name: "acme-web", ClientId: "acme-web", Organization: "hanzo", SigninUrl: good}
		if _, err := Update(db)(ctx, up); err != nil {
			t.Errorf("update refused signinUrl %q: %v", good, err)
		}
	}
}

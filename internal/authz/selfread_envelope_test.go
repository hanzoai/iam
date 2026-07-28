// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package authz

import "testing"

// SELF-READ. An app may read the row it authenticated as — the ordinary bootstrap
// of an OIDC relying party — and nothing else. The owner-pin that closed the
// "every client credential is a global admin" escalation was missing this one case,
// so a confidential client could not read even itself and every cloud deploy 403'd.
//
// The grant is keyed on BOTH halves of (AppOwner, App), which is what keeps it a
// self-read rather than "apps may read applications".
func TestAuthorize_AppReadsOnlyItsOwnRecord(t *testing.T) {
	cloud := &Principal{App: "hanzo-cloud", AppOwner: "admin", Org: "hanzo"}

	for _, tc := range []struct {
		name                  string
		p                     *Principal
		method, owner, target string
		want                  bool
		why                   string
	}{
		{"its own record", cloud, "GET", "admin", "hanzo-cloud", true,
			"an app must be able to bootstrap from its own registration"},

		// The two collision directions the owner-pin exists to separate. Both were
		// 403 before this change and must STAY 403.
		{"same name, tenant owner", cloud, "GET", "hanzo", "hanzo-cloud", false,
			"a tenant-registered app of the same NAME is a different row"},
		{"sibling in the same owner", cloud, "GET", "admin", "hanzo-console", false,
			"reading a sibling would make this 'apps may read applications'"},
		{"another tenant's app", cloud, "GET", "acme", "acme-thing", false,
			"cross-tenant read"},

		// Read only. A write to its own row would let a client widen its own
		// redirect URIs or grant types — self-escalation.
		{"write to its own record", cloud, "POST", "admin", "hanzo-cloud", false,
			"self-read must never become self-write"},
		{"delete its own record", cloud, "DELETE", "admin", "hanzo-cloud", false,
			"self-read must never become self-delete"},

		// The grant is scoped to the applications entity alone.
		{"users under its own owner", cloud, "GET", "admin", "hanzo-cloud", false,
			"the entity is users here, not applications"},

		// An app with no owner pin holds nothing (the fail-closed default).
		{"unpinned app", &Principal{App: "hanzo-cloud"}, "GET", "admin", "hanzo-cloud", false,
			"an app whose AppOwner is empty matches no row"},
		{"empty owner target", cloud, "GET", "", "hanzo-cloud", false,
			"an empty owner must never match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entity := "applications"
			if tc.name == "users under its own owner" {
				entity = "users"
			}
			if got := authorize(tc.p, tc.method, entity, tc.owner, tc.target); got != tc.want {
				t.Errorf("authorize(%s %s %s/%s) = %v, want %v — %s",
					tc.method, entity, tc.owner, tc.target, got, tc.want, tc.why)
			}
		})
	}
}

// A HUMAN is unaffected by the self-read clause: their authority is still decided
// by the org policy below it, so a tenant user cannot read a platform app row.
func TestAuthorize_SelfReadDoesNotLeakToHumans(t *testing.T) {
	human := &Principal{Org: "hanzo", User: "alice", Admin: true}
	if authorize(human, "GET", "applications", "admin", "hanzo-cloud") {
		t.Errorf("an org admin read a platform-owned application row")
	}
}

// ONE ENVELOPE PER SURFACE. The compat verbs are verb-shaped and their clients
// branch on a STRING status; the native surface is noun-shaped and keeps zip's
// numeric-status error.
func TestLegacyVerb_SelectsTheCompatSurfaceOnly(t *testing.T) {
	for path, want := range map[string]bool{
		"/v1/iam/get-account":       true,
		"/v1/iam/get-application":   true,
		"/v1/iam/add-organization":  true,
		"/v1/iam/update-user":       true,
		"/v1/iam/delete-membership": true,
		"/v1/iam/users":             false, // native REST noun
		"/v1/iam/organizations":     false,
		"/v1/iam/oauth/token":       false, // RFC 6749 shape
		"/v1/iam/scim/v2/Users/x":   false, // RFC 7644 shape
		"/healthz":                  false,
		"/v1/iam/":                  false,
		"/v1/other/get-thing":       false, // not the IAM surface
	} {
		if got := legacyVerb(path); got != want {
			t.Errorf("legacyVerb(%q) = %v, want %v", path, got, want)
		}
	}
}

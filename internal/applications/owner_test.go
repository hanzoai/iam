// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications_test

import "testing"

// The org an application SERVES is the org every app token it mints carries, so a
// SuperAdmin — who may point an app at any org — may still only point it at an
// org name. "Admin" is not one: it names no org and reads as the reserved one to
// anything that folds case.
func TestCreate_OrganizationIsAnOrgName(t *testing.T) {
	h := newOrgHarness(t)
	root := h.token(t, "admin/root")
	for i, org := range []string{"Admin", "ADMIN", "Hanzo", "ac/me"} {
		body := `{"owner":"admin","name":"case-` + string(rune('a'+i)) + `","organization":"` + org + `","clientId":"case-` + string(rune('a'+i)) + `"}`
		if st := h.do(t, "POST", "/v1/iam/applications", root, body); st < 400 {
			t.Errorf("an application serving %q: status=%d, want a refusal", org, st)
		}
	}
	if st := h.do(t, "POST", "/v1/iam/applications", root, `{"owner":"admin","name":"case-ok","organization":"hanzo","clientId":"case-ok"}`); st != 200 {
		t.Fatalf("an application serving hanzo: status=%d, want 200", st)
	}
}

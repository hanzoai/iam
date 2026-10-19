// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package serviceaccounts_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/store"
)

// A service account is filed under the org it is created for, and that org is the
// one its credential acts in. Only an org name may be one: a SuperAdmin, who may
// create in any org, could otherwise file a machine under "Admin" — an org that
// does not exist and that a case-folding reader takes for the reserved one.
func TestCreate_RefusesAnOrganizationThatIsNotAnOrgName(t *testing.T) {
	h := newHarness(t)
	root := h.token(t, "admin/root")
	for _, org := range []string{"Admin", "ADMIN", "Hanzo", "ac/me"} {
		req := httptest.NewRequest("POST", path, strings.NewReader(`{"organization":"`+org+`","name":"bot"}`))
		req.Host = "hanzo.id"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+root)
		resp, err := testhttp.Do(h.app, req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if strings.Contains(string(body), `"status":"ok"`) {
			t.Errorf("organization %q: a service account was created: %s", org, body)
		}
		for _, name := range []string{"bot", strings.ToLower(org) + "-bot", org + "-bot"} {
			if u, _ := store.GetUserByName(req.Context(), h.db, org, name); u != nil {
				t.Errorf("organization %q: %s/%s exists after the refusal", org, u.Owner, u.Name)
			}
		}
	}
}

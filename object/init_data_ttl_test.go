// Copyright © 2026 Hanzo AI. MIT License.

package object

import "testing"

// TestReconcileApplicationOAuthTTL pins the token-TTL reconcile policy: the
// seed (`desired`) is AUTHORITATIVE for both the access-token and refresh-token
// lifetimes. It must not only FILL an invalid/missing value but also TIGHTEN or
// CORRECT an over-long one — the fix for a stored 168h (7-day) access token that
// the old fill-if-invalid guard (`existing <= 0`) could never shorten, leaving a
// week-long standing-risk window on every stateless JWT. Decomplected from the
// DB write (reconcileApplicationOAuthDefaults is pure), so it needs no ormer,
// cert, or config — same pattern as TestTokenAudience.
func TestReconcileApplicationOAuthTTL(t *testing.T) {
	has := func(cols []string, name string) bool {
		for _, c := range cols {
			if c == name {
				return true
			}
		}
		return false
	}

	cases := []struct {
		name          string
		existExpire   float64
		seedExpire    float64
		wantExpireCol bool
		wantExpire    float64
		existRefresh  float64
		seedRefresh   float64
		wantRefCol    bool
		wantRefresh   float64
	}{
		// THE FIX: an over-long stored access token is tightened to the seed's 1h.
		{"tighten access 7d->1h", 168, 1, true, 1, 720, 720, false, 720},
		// Still fills an invalid/missing value (backward-compatible with the old guard).
		{"fill invalid access -1->1", -1, 1, true, 1, -1, 720, true, 720},
		{"fill zero access 0->24", 0, 24, true, 24, 0, 720, true, 720},
		// Idempotent: already-correct values produce no update (no needless write).
		{"idempotent access 1==1", 1, 1, false, 1, 720, 720, false, 720},
		// Seed silent (0) => PRESERVE existing; never zero a live app's TTL.
		{"seed unset preserves access", 168, 0, false, 168, 720, 0, false, 720},
		// Seed is source of truth in BOTH directions (can also extend if declared).
		{"seed extends access 1->8", 1, 8, true, 8, 168, 720, true, 720},
		// Refresh is reconciled by the same rule (retention backstop stays seed-owned).
		{"tighten refresh 60d->30d", 1, 1, false, 1, 1440, 720, true, 720},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			existing := &Application{
				Owner: "admin", Name: "hanzo-console",
				ExpireInHours: tc.existExpire, RefreshExpireInHours: tc.existRefresh,
			}
			desired := &Application{
				Owner: "admin", Name: "hanzo-console",
				ExpireInHours: tc.seedExpire, RefreshExpireInHours: tc.seedRefresh,
			}

			cols := reconcileApplicationOAuthDefaults(existing, desired)

			if got := has(cols, "expire_in_hours"); got != tc.wantExpireCol {
				t.Fatalf("expire_in_hours in updateCols = %v, want %v (cols=%v)", got, tc.wantExpireCol, cols)
			}
			if existing.ExpireInHours != tc.wantExpire {
				t.Fatalf("ExpireInHours = %v, want %v", existing.ExpireInHours, tc.wantExpire)
			}
			if got := has(cols, "refresh_expire_in_hours"); got != tc.wantRefCol {
				t.Fatalf("refresh_expire_in_hours in updateCols = %v, want %v (cols=%v)", got, tc.wantRefCol, cols)
			}
			if existing.RefreshExpireInHours != tc.wantRefresh {
				t.Fatalf("RefreshExpireInHours = %v, want %v", existing.RefreshExpireInHours, tc.wantRefresh)
			}
		})
	}
}

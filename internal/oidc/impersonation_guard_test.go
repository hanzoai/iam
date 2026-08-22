// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"
)

// The port of the iam-v1 fixes c904dc0a + 0e5485a5 ("app principal can't
// impersonate its way to admin/super via ?userId") into the iam architecture.
//
// iam-v1 let an "app/<name>" confidential client set ?userId=<owner>/<name> on the
// identity endpoints and RequireAdmin routes, then derived admin/super authority
// from the RESOLVED user — so ?userId=admin/z made the app a platform SuperAdmin.
//
// iam has NO ?userId override anywhere: userinfo/whoami/get-account take the
// subject from the VERIFIED JWT `sub` (oidc.callerOf / splitSub(claims.Subject)),
// and an app principal is never Admin/Super — its whole authority is its capability
// allowlist (authz.app / authz.authorize: `if p.App != "" { return Allowed(...) }`).
// The one surface where a confidential client acts on an ARBITRARY named user is the
// on-behalf-of mint (issue-user-token / mint-user-keys), targeted by ?id=<owner>/<name>.
// That is the iam analogue of iam-v1's ?userId, and the escalation-blocking guard is
// mintTarget's reserved-org gate (issuetoken.go):
//
//	if policy.IsSigningOwner(owner) && !adminMintAllowed(clientApp) { return 403 }
//
// i.e. reaching a reserved-org (admin/built-in => SuperAdmin) target requires the
// SEPARATELY-granted admin-mint capability, never the general mint list. These
// tests pin that boundary end-to-end so deleting the reserved-org gate (which would
// let a general minter mint for admin/z, exactly the iam-v1 super spoof) FAILS here.

// TestImpersonation_generalMinter_cannotReachAdminOrgTarget is the exploit-blocking
// case: an app that IS on the general key-mint allow-list but NOT on the admin-mint
// list tries to mint a token impersonating a real admin-org SuperAdmin (admin/z).
// The reserved-org gate refuses it with 403 — no token is ever minted for a
// SuperAdmin identity. This is the direct analogue of iam-v1's "app set
// ?userId=admin/z to become super". Remove the gate at issuetoken.go and this flips
// to 200 → test fails.
func TestImpersonation_generalMinter_cannotReachAdminOrgTarget(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console") // general minter …
	// … deliberately NOT on IAM_ADMIN_MINT_ALLOWED_APPS (unset ⇒ fail-closed).
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"}) // admin-owned console
	seedUserInOrg(t, db, "admin", "z", "z@hanzo.ai", "pw")                   // a real SuperAdmin (org == admin)

	// issue-user-token: the read-only mint (no row mutation) that exercises the same
	// authorizeMinter → mintTarget seam as mint-user-keys.
	resp, body := do(t, app, keyReq("POST", PathTokensIssue, "hanzo-console", "top-secret", "?id=admin/z"))
	if resp.StatusCode != 403 {
		t.Fatalf("SUPER SPOOF: general minter reached admin-org target admin/z (status=%d) — an app impersonated a SuperAdmin; body=%s",
			resp.StatusCode, body)
	}
	if _, ok := decode(t, body)["accessToken"]; ok {
		t.Fatalf("SUPER SPOOF: a token was minted for the SuperAdmin admin/z; body=%s", body)
	}

	// mint-user-keys hits the SAME gate and additionally mutates the row — prove it is
	// refused too, so a leaked general-minter secret can neither mint a super token nor
	// rotate a super's durable API key.
	resp, body = do(t, app, keyReq("POST", userKeys("admin/z"), "hanzo-console", "top-secret", ""))
	if resp.StatusCode != 403 {
		t.Fatalf("SUPER SPOOF: general minter rotated the SuperAdmin admin/z's key (status=%d); body=%s",
			resp.StatusCode, body)
	}
}

// The id-shaped gate is what keeps this endpoint from reporting who exists in a
// reserved org, and it is the half the test above cannot see.
//
// Two gates carry the same refusal twenty lines apart: one asks the id AS WRITTEN
// before any read, the other asks the RESOLVED identity after it. For a target
// that exists they agree, so deleting the first leaves every test in this package
// passing — measured. What only the first can answer is a name that is NOT there:
// with it, admin/ghost is refused 403 like any reserved target; without it, the
// read runs and answers `200 the user does not exist`, and an unprivileged client
// can tell a real SuperAdmin from an invented one by the shape of the refusal.
func TestImpersonation_reservedTarget_isNoExistenceOracle(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUserInOrg(t, db, "admin", "z", "z@hanzo.ai", "pw") // exists
	// admin/ghost is deliberately never seeded.

	ask := func(id string) (int, string) {
		resp, body := do(t, app, keyReq("POST", PathTokensIssue, "hanzo-console", "top-secret", "?id="+id))
		return resp.StatusCode, string(body)
	}
	existsStatus, existsBody := ask("admin/z")
	ghostStatus, ghostBody := ask("admin/ghost")

	if existsStatus != 403 || ghostStatus != 403 {
		t.Fatalf("reserved targets must both be 403: admin/z=%d admin/ghost=%d", existsStatus, ghostStatus)
	}
	// Same answer, or the difference IS the oracle.
	if existsBody != ghostBody {
		t.Fatalf("a reserved target that exists answers differently from one that does not:\n exists: %s\n ghost:  %s",
			existsBody, ghostBody)
	}
}

// TestImpersonation_adminMinter_boundaryIsTheAdminMintCapability is the paired
// positive: the SAME target (admin/z) IS reachable once the app holds the separately
// granted admin-mint capability. This proves the reserved-org refusal above is a
// precise capability boundary (the ONE way to act for a reserved-org user), not an
// incidental failure — mirroring iam-v1, where the admin-mint list is the sole path
// to a privileged target.
func TestImpersonation_adminMinter_boundaryIsTheAdminMintCapability(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	t.Setenv("IAM_ADMIN_MINT_ALLOWED_APPS", "hanzo-console") // now ALSO admin-mint capable
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUserInOrg(t, db, "admin", "z", "z@hanzo.ai", "pw")

	resp, body := do(t, app, keyReq("POST", PathTokensIssue, "hanzo-console", "top-secret", "?id=admin/z"))
	if resp.StatusCode != 200 {
		t.Fatalf("admin-mint-capable console must reach admin/z (status=%d); body=%s", resp.StatusCode, body)
	}
	access, _ := dataMap(t, body)["accessToken"].(string)
	if access == "" {
		t.Fatalf("no accessToken for the admin-mint-capable console; body=%s", body)
	}
}

// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz

import (
	"os"
	"strings"

	"github.com/hanzoai/iam/internal/store"
)

// Confidential-client capabilities — the port of the v1 gate (object/app_authz.go
// + controllers/app_mutation_guard.go requireAppCapability) that revoked the
// "every client credential is a global admin" privilege.
//
// A Cap is a named authority an app principal holds ONLY when its application
// name is listed in the allowlist Env names. It is the ONLY thing an app
// principal's authority is made of: an app is never a SuperAdmin and never an
// org admin (see Principal), so a leaked client credential grants exactly the
// capabilities its NAME was allowlisted for and nothing more.
//
// The key is the application NAME, not its (owner, name) row. That alone would let
// ANY owner's app claim a listed name, so Allowed ALSO pins the app's OWNING org to
// a reserved platform signing owner (store.IsSigningCertOwner): the name is thereby
// reserved to the platform's admin-owned app, and a tenant that registers
// <theirOrg>/hanzo-console — same name, its own owner — inherits none of its grants.
// The pin is what ENFORCES that reservation; the name match alone was the escalation.

// Cap is one capability: a Name for diagnostics and the Env var holding its
// comma-separated allowlist of application names.
type Cap struct {
	Name string
	Env  string
}

// The capability set, matching the live allowlists byte-for-byte
// (universe infra/k8s/operator/crs/iam.yaml). Every one is fail-secure: an unset
// or empty allowlist denies EVERY app.
var (
	// CapKeyMint gates minting, rotating, or revoking a credential on another
	// principal's behalf — the service-account administration boundary, since a
	// minted key is an org-billing credential.
	CapKeyMint = Cap{Name: "key-mint", Env: "IAM_KEY_MINT_ALLOWED_APPS"}

	// CapUserAdmin gates cross-user account mutation (owner, isAdmin, email,
	// type, credentials) — cloud moves an onboarding user into the org it just
	// created through this.
	CapUserAdmin = Cap{Name: "user", Env: "IAM_USER_ADMIN_APPS"}

	// CapOrgAdmin gates organization create/read/update/delete. Unlike the
	// signing-material capabilities this one is populated in every environment:
	// the brand consoles legitimately create customer orgs during onboarding.
	CapOrgAdmin = Cap{Name: "organization", Env: "IAM_ORG_ADMIN_APPS"}

	// CapServiceAccountRead gates LISTING an org's service accounts — names and
	// metadata only, never secrets. It is the read-only counterpart to
	// CapKeyMint (a read cap can never mint, rotate, or delete a credential) and
	// is additionally tenant-bound by BoundToOrg.
	CapServiceAccountRead = Cap{Name: "service-account-read", Env: "IAM_SA_LIST_ALLOWED_APPS"}

	// CapKeyResolve gates resolving an opaque API key (hk-/pk-/sk-) to its owning
	// principal via get-user?accessKey. It is a CREDENTIAL-DISCLOSURE boundary: the
	// caller presents a secret key and learns WHO it authenticates, so it must never
	// be an arbitrary authenticated caller. The intended sole holder is the cloud
	// identity boundary (SanitizeIdentity), which turns a keyed request into the same
	// principal a JWT yields. Fail-secure exactly like the others: an unset or empty
	// allowlist lets NO app resolve a key. Enforced additionally as app-only at the
	// handler (a human, even a SuperAdmin, holds a capability vacuously — so the key
	// path also requires p.App != "" to keep this a service-only door).
	//
	// Keyed on the application NAME (via Allowed → p.App), matching all four sibling
	// Caps above — the ONE way capabilities are matched in this family. RED F3 asked
	// whether it should key on clientId like the issuetoken mint verbs (appInList);
	// deliberately NOT, because (1) that is a DIFFERENT, older mechanism, so making
	// CapKeyResolve clientId-based would make it the sole clientId-keyed Cap —
	// inconsistent with its own family — and (2) it would require adding ClientId to
	// the Principal shape. The owner-pin (Allowed requires AppOwner ∈ signing owners)
	// already defeats the name-collision vector: a tenant app that reuses a listed
	// name is not a signing owner and holds nothing. Under the <org>-<app> convention
	// name == clientId, so the two are equivalent in practice. Gate unchanged.
	CapKeyResolve = Cap{Name: "key-resolve", Env: "IAM_KEY_RESOLVE_APPS"}
)

// Allowed reports whether p holds c.
//
// A non-app principal holds every capability vacuously: this gate concerns
// confidential clients ONLY, and a human's authority is decided by the org
// policy in authorize(). Conflating the two would either lock every human out or
// hand every app a human's scope.
//
// Fail-secure, exactly as v1: an app whose allowlist is unset, empty, or does
// not name it holds nothing.
func Allowed(p *Principal, c Cap) bool {
	if p == nil {
		return false
	}
	if p.App == "" {
		return true // not an app; the org policy decides
	}
	// The owner-pin: an app holds a platform capability ONLY when its OWNING org is a
	// reserved platform signing owner (admin/built-in). Every allow-listed console is
	// admin-owned, so this never revokes a legitimate grant — but it binds the NAME
	// allowlist to the platform: a tenant that registers <theirOrg>/hanzo-console
	// (same name, its OWN owner) is not a signing owner, so it inherits nothing. This
	// is the single gate that turns the allowlist's NAME key from a spoofable label
	// into an authority reserved to the admin-owned app.
	if !store.IsSigningCertOwner(p.AppOwner) {
		return false
	}
	if c.Env == "" {
		return false
	}
	for _, item := range strings.Split(os.Getenv(c.Env), ",") {
		if strings.TrimSpace(item) == p.App {
			return true
		}
	}
	return false
}

// BoundToOrg reports whether an app principal is bound to org by the
// <org>-<app> naming convention — app/hanzo-team may act on organization=hanzo
// and on no other tenant's. The org is derived from the (allowlist-reserved)
// application NAME, so the binding holds regardless of the app row's owner, and
// it is the same prefix rule the service-account names it reads obey.
func BoundToOrg(p *Principal, org string) bool {
	if p == nil || org == "" {
		return false
	}
	prefix := org + "-"
	return len(p.App) > len(prefix) && strings.HasPrefix(p.App, prefix)
}

// capFor maps an entity to the capability a confidential client needs to act on
// it. An entity with NO mapping grants an app nothing: unmapped denies exactly
// as an unset allowlist does, which IS v1's live behaviour for every capability
// the deployment leaves empty — certs, providers, tokens, syncers, webhooks are
// all deny-all by design, because no client credential should ever reach signing
// material. Only the two entities a live confidential client touches are mapped:
// the brand consoles create customer orgs, and cloud moves the onboarding user
// into the org it just created.
func capFor(entity string) Cap {
	switch entity {
	case "organizations":
		return CapOrgAdmin
	case "users":
		return CapUserAdmin
	}
	return Cap{}
}

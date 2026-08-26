// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/keys"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// credentialType is the User.Type discriminator for the tenant's default API
// credential — a service account. It MUST match the serviceaccounts package's own
// discriminator; oidc cannot import that package (authz→oidc would cycle), so the
// value is stated here and the two are kept in step by that contract.
const credentialType = "service-account"

// provision idempotently converges a self-service signup to ONE tenant: an
// organization, its founding user as that org's own admin, and ONE org-scoped API
// key. It is the single provisioning primitive the onboarding endpoint drives —
// every step is an ENSURE (converge), never a bare CREATE (conflict):
//
//   - org:  query by name, create when absent, stamping the caller as Founder.
//   - user: the caller is moved into <slug> as its admin; already-there is a no-op.
//           The caller's own new org, NOT the reserved admin org — provision, do
//           not promote (the reserved-slug gate forbids admin/built-in/app).
//   - account: the org's own service account "<slug>-default", so the gateway meters
//           every request under the org and a provisioned tenant is NEVER unmetered.
//   - key:  the credential that account presents, at "<slug>/<slug>-default-key" —
//           the row a presented secret is resolved through. Ensured apart from the
//           account, because the two are separate rows and a tenant can hold one
//           without the other. A second call returns the SAME key, never a second
//           one, and never re-reveals the secret.
//
// RETRY / PARTIAL-FAILURE convergence is backend-portable — it does NOT depend on a
// transaction rolling back (production runs a store where each write autocommits
// independently). The Founder stamp is the resume token: if a prior attempt created
// the org but failed before moving the caller in, a retry recognises the org as the
// caller's OWN (org.Founder == caller) and completes it, instead of stranding on a
// permanent "already exists" 409. So an interrupted signup CONVERGES to one org +
// admin + key on any backend.
//
// Tenant isolation: a pre-existing org is the caller's to complete iff the caller
// already admins it OR founded it; any other pre-existing org is refused 409. A
// caller can never join, read, or hijack another tenant's org.
//
// CONCURRENCY NOTE: on SQLite (the embedded/dev backend) the enclosing transaction
// serializes racing onboards, so two identities racing one slug resolve to a single
// winner. On a pure-autocommit backend WITHOUT a serializing transaction, closing
// the concurrent-create window needs an atomic conditional write the ORM does not
// yet expose at its portable DB seam (see the store escalation) — the Founder resume
// bounds the damage (a loser can never complete the org) but a same-instant race can
// still transiently co-admit; that residual is tracked for the store layer.

// claim is the caller identity plus the org it is claiming. owner/name identify the
// caller (an IAM user's org IS its identity, so owner is the caller's current org);
// slug/display/personal describe the target org, already slug-validated and
// reserved-checked by the handler.
type claim struct {
	owner, name   string
	slug, display string
	personal      bool
}

// provisioned is the converged tenant state provision returns. accessSecret is set
// ONLY when this call newly minted the key (shown once); an idempotent replay
// returns the publishable accessKey but never re-reveals the secret. The org starts
// at a ZERO balance — usage is pre-paid, so there is no signup grant.
type provisioned struct {
	org                     string
	accessKey, accessSecret string
	orgCreated, keyCreated  bool
	// movedFrom is the org the caller belonged to BEFORE the converge. When it
	// differs from org the caller's identity was re-keyed ("<owner>/<name>"), which
	// invalidates every credential that names the old pair — the session cookie
	// above all. The onboard endpoint reads it to re-issue that cookie so a human
	// stays signed in across their own signup.
	movedFrom string
}

// fault is a provisioning failure carrying the HTTP status the onboarding contract
// maps to res.ok=false, so provision returns ONE error channel while the handler
// still renders the right status. A non-fault error from the tx is a 500.
type fault struct {
	status int
	msg    string
}

func (f *fault) Error() string { return f.msg }

// provision runs the idempotent converge described on the package doc above.
func provision(ctx context.Context, db orm.DB, cl claim) (provisioned, error) {
	// Provision, do NOT promote (defense in depth, independent of the handler's own
	// gate): a self-service tenant may never be provisioned into a reserved system
	// org — above all the reserved `admin` SuperAdmin org. This is the security
	// primitive every caller inherits, so the property holds even if a future caller
	// forgets the check.
	if len(cl.slug) < minOrgSlug {
		return provisioned{}, &fault{400, "org name too short"}
	}
	if policy.IsReservedOrg(cl.slug) {
		return provisioned{}, &fault{400, "\"" + cl.slug + "\" is reserved"}
	}

	var out provisioned
	err := db.RunInTransactionWith(ctx, &orm.TxOptions{MaxAttempts: 5}, func(tx orm.DB) error {
		// Resolve the caller by (owner, name). A user's storage id is a surrogate and
		// the move re-keys only the Owner FIELD, so the caller is found by query — and
		// under the target slug too: a retry whose pre-move credential is stale (the
		// move already landed but its response was lost) still resolves the moved
		// identity, so the replay converges instead of failing "user does not exist".
		user, err := store.GetUserByName(ctx, tx, cl.owner, cl.name)
		if err != nil {
			return &fault{500, "server_error"}
		}
		if user == nil {
			if u, e := store.GetUserByName(ctx, tx, cl.slug, cl.name); e == nil {
				user = u
			}
		}
		if user == nil {
			return &fault{400, "the user does not exist"}
		}
		founder := user.Model.Id() // stable surrogate storage id — survives the Owner re-key

		// First-run gate. Onboarding MOVES the caller into the new org, so founding a
		// SECOND org would strip the caller from — and orphan — the org it already
		// admins (its live billing account + metered key left with no owner). A caller
		// that already admins its OWN org may only re-drive THAT org (idempotent);
		// additional orgs are a separate (membership) flow. A brand-new signup (admin
		// of nothing yet) is first-run and passes.
		if user.IsAdmin && user.Owner != cl.slug {
			return &fault{409, "you already have an organization; additional orgs are added separately"}
		}

		// Ensure the org by its (Owner="admin", Name=slug) natural key, stamping the
		// founder on create.
		org, err := store.GetOrganizationByName(ctx, tx, cl.slug)
		if err != nil {
			return &fault{500, "server_error"}
		}
		orgCreated := org == nil
		if orgCreated {
			o := orm.New[schema.Organization](tx)
			o.Owner = "admin"
			o.Name = cl.slug
			o.DisplayName = cl.display
			o.IsPersonal = cl.personal
			o.Founder = founder
			o.CreatedTime = provisionNow()
			o.SetId("admin/" + cl.slug)
			if err := o.CreateCtx(ctx); err != nil {
				return &fault{500, "server_error"}
			}
		}
		out.orgCreated = orgCreated

		// Tenant isolation + partial-failure RESUME — backend-portable, no reliance on
		// transaction rollback (production autocommits each write independently). A
		// pre-existing org is the caller's to complete iff the caller already admins it
		// (fully provisioned replay) OR founded it (its Founder stamp is this caller —
		// a prior attempt created the org but the move did not land). Any other
		// pre-existing org belongs to another tenant → refuse. So an interrupted signup
		// RESUMES to one org + admin instead of stranding on a permanent 409, and a
		// second identity can never complete, join, or hijack the org.
		if !orgCreated && !(user.Owner == cl.slug && user.IsAdmin) && org.Founder != founder {
			return &fault{409, "the organization \"" + cl.slug + "\" already exists"}
		}

		// Move the caller into the org as its admin (changing Owner re-keys the
		// identity; lookups are by (owner, name)). Already-there is a no-op that skips
		// the write. The org's balance starts at zero — usage is pre-paid.
		wasOwner := user.Owner
		if user.Owner != cl.slug || !user.IsAdmin {
			user.Owner = cl.slug
			user.IsAdmin = true
			user.UpdatedTime = provisionNow()
			if err := user.UpdateCtx(ctx); err != nil {
				return &fault{500, "server_error"}
			}
		}
		out.movedFrom = wasOwner

		// Ensure ONE org-scoped, metered credential — a service account whose secret
		// is stored as a DIGEST (never plaintext) and revealed exactly once, on mint.
		// Org-scoped (Owner=slug), so the gateway meters every request under the org;
		// the tenant can never call unmetered. Idempotent: a replay returns the
		// credential's publishable half, never a second one and never the secret
		// again.
		// A credential is a user row, so its name obeys THE username rule like any
		// other principal's. The slug is already lowercase and bounded to leave room
		// for the suffix (maxOrgSlug), so this refuses nothing that onboarding can
		// legitimately reach — it states the invariant the derivation relies on.
		saName, err := schema.Username(cl.slug + "-default")
		if err != nil {
			return &fault{400, err.Error()}
		}
		sa, err := store.GetUserByName(ctx, tx, cl.slug, saName)
		if err != nil {
			return &fault{500, "server_error"}
		}
		if sa == nil {
			sa = orm.New[schema.User](tx)
			sa.Owner, sa.Name = cl.slug, saName
			sa.Type, sa.DisplayName = credentialType, "Default API key"
			sa.CreatedTime = provisionNow()
			sa.SetId(cl.slug + "/" + saName)
			if err := sa.CreateCtx(ctx); err != nil {
				return &fault{500, "server_error"}
			}
		}

		// The account and the credential it presents are ensured SEPARATELY, because
		// they are two rows and a tenant can hold one without the other. The account
		// used to answer for both: a tenant whose account existed was taken to hold a
		// working credential, and the credential itself went onto the account's own
		// User row — a row nothing resolves a secret from. Asking the row a presented
		// secret is actually RESOLVED through is what makes the converge true, and it
		// carries every tenant already in that state to a credential that works.
		//
		// keys.MintAccountKey is the one call every account credential is issued by,
		// so a rotation later replaces this exact row rather than leaving a second
		// live one beside it.
		k, err := orm.Get[schema.Key](tx, cl.slug+"/"+saName+"-key")
		if err != nil && !errors.Is(err, orm.ErrNotFound) {
			return &fault{500, "server_error"}
		}
		keyCreated := errors.Is(err, orm.ErrNotFound)
		if keyCreated {
			accessKey, secret, mErr := keys.MintAccountKey(ctx, tx, cl.slug, saName)
			if mErr != nil {
				return &fault{500, "server_error"}
			}
			out.accessKey = accessKey
			out.accessSecret = secret // shown once, on the mint that issues it
		} else {
			// A replay names the publishable half of the credential the account
			// already holds, and never re-reveals the secret.
			out.accessKey = k.AccessKey
		}

		// Record the founder ON the org's roster. The move alone makes the caller the
		// org's admin, and MemberOrgRefs already emits a HOME org from the user row —
		// but the (User × Org) relation is what an org's ROSTER is read from
		// (MembershipsByOrg: invitations, team management, the org-switch grant), so
		// without this row a self-service org is born with nobody on it. RoleOwner, not
		// admin: the founder is the org's owner, and EnsureMembership never downgrades,
		// so a later home-org backfill (which would write RoleAdmin) can no longer
		// quietly demote them. Idempotent on the (user, org) pair, so a replay adds
		// nothing.
		if _, err := store.EnsureMembership(ctx, tx, cl.slug+"/"+cl.name, cl.slug, store.RoleOwner); err != nil {
			return &fault{500, "server_error"}
		}
		// The move RE-KEYS the caller (user ids are "<owner>/<name>"), which strands
		// the membership row filed under the OLD id: it names an identity that no
		// longer exists, so the previous org's roster keeps a ghost member forever.
		// Drop it in the same converge that re-keyed the user — one identity, one set
		// of memberships. Idempotent (a missing row reports false, never an error).
		if wasOwner != cl.slug {
			if _, err := store.DeleteMembership(ctx, tx, wasOwner+"/"+cl.name, wasOwner); err != nil {
				return &fault{500, "server_error"}
			}
		}
		out.org = cl.slug
		out.keyCreated = keyCreated
		return nil
	})
	if err != nil {
		return provisioned{}, err
	}
	return out, nil
}

// provisionNow is the RFC3339 string timestamp for a freshly created/updated row,
// matching the v1-compatible stamp onboarding writes elsewhere.
func provisionNow() string { return time.Now().UTC().Format(time.RFC3339) }

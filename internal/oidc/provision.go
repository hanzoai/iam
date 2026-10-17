// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/keys"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// provision idempotently founds an organization: the org, its founder as its
// owner, and ONE API key the founder holds in it. Every step is an ENSURE
// (converge), never a bare CREATE (conflict):
//
//   - org:  query by name, create when absent, stamping the caller as Founder.
//   - user: onboarding leaves the caller's account where it is — who they are and
//           how they sign in do not change — and they own the org by membership.
//           A signup at a founding application (Charter, claim.move) instead
//           MOVES the account it just made into the org it works in, as that
//           org's admin; already-there is a no-op. Never the reserved admin org —
//           provision, do not promote (the reserved-slug gate forbids
//           admin/built-in/app).
//   - key:  the founder's default key, the row "<slug>/default" labelled "Default",
//           held by the founder and filed in the org, so a request made with it
//           speaks for the founder and is metered under the org. Ensured by that
//           row: a second call returns the SAME key, never a second one, and never
//           re-reveals the secret.
//
// Onboarding never moves anyone because a move re-keys the account to
// "<slug>/<name>", and sign-in looks an address up in the signup org: the person
// who founded an org at hanzo.id or platform.hanzo.ai was then told their address
// had no account and offered a second one.
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
// reserved-checked by the handler. move is a signup's founding (Charter): the
// account it just made works in the org it founds. Onboarding leaves it unset.
type claim struct {
	owner, name   string
	slug, display string
	personal      bool
	move          bool
}

// provisioned is the converged tenant state provision returns. accessSecret is set
// ONLY when this call newly minted the key (shown once); an idempotent replay
// returns the publishable accessKey but never re-reveals the secret. The org starts
// at a ZERO balance — usage is pre-paid, so there is no signup grant.
type provisioned struct {
	org                     string
	accessKey, accessSecret string
	orgCreated, keyCreated  bool
	// movedFrom is the org a moved caller belonged to BEFORE the converge, and empty
	// when nobody moved. When it differs from org the caller's identity was re-keyed
	// ("<owner>/<name>"), which invalidates every credential that names the old
	// pair — the session cookie above all — so the caller re-issues that cookie and
	// a human stays signed in across their own signup.
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
	if policy.IsHeldOrg(cl.slug) {
		return provisioned{}, &fault{400, "\"" + cl.slug + "\" is reserved"}
	}

	if _, err := schema.OrgDisplayName(cl.display); err != nil {
		return provisioned{}, &fault{400, err.Error()}
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
		if user.IsForbidden || user.IsDeleted {
			return &fault{403, "a suspended account founds no organization"}
		}
		founder := user.Model.Id() // stable surrogate storage id — survives the Owner re-key

		// A platform operator holds no role in a customer org, and an account of a
		// reserved org is never recorded as one's member.
		if policy.IsReservedOrg(user.Owner) {
			return &fault{403, "a SuperAdmin cannot own a customer organization"}
		}
		// The move's first-run gate. Moving a caller who already admins their own
		// org would strip them from — and orphan — that org (its live billing account
		// + metered key left with no owner), so a move re-drives only the org the
		// caller already lives in. A brand-new signup (admin of nothing yet) passes.
		if cl.move && user.IsAdmin && user.Owner != cl.slug {
			return &fault{409, "you already have an organization; additional orgs are added separately"}
		}
		// The identity the org's owner membership and default key name: the
		// account where it lives after this converge.
		home := user.Owner
		if cl.move {
			home = cl.slug
		}
		holder := home + "/" + user.Name

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
			// Rows a removed org of this name left behind would come with it.
			if held, err := store.OrgHeld(ctx, tx, cl.slug); err != nil {
				return &fault{500, "server_error"}
			} else if held {
				return &fault{409, "the organization \"" + cl.slug + "\" already exists"}
			}
			// One account founds at most store.MaxFoundedOrgs organizations, as the
			// membership surface holds it: each holds its name for good.
			if over, err := store.FoundTooMany(ctx, tx, founder); err != nil {
				return &fault{500, "server_error"}
			} else if over {
				return &fault{409, fmt.Sprintf("an account founds at most %d organizations", store.MaxFoundedOrgs)}
			}
			// Create-only: an org another request wrote after the read above is
			// judged below like any org that already existed, never overwritten.
			created, err := store.InsertOrganization(ctx, tx, o)
			if err != nil {
				return &fault{500, "server_error"}
			}
			if !created {
				if org, err = store.GetOrganizationByName(ctx, tx, cl.slug); err != nil || org == nil {
					return &fault{500, "server_error"}
				}
				orgCreated = false
			}
		}
		out.orgCreated = orgCreated

		// Tenant isolation + partial-failure RESUME — backend-portable, no reliance on
		// transaction rollback (production autocommits each write independently). A
		// pre-existing org is the caller's to complete iff the caller already admins it
		// (a moved founder's replay) OR founded it — its Founder stamp is this caller —
		// and nobody else owns it: its roster is empty (a prior attempt did not finish)
		// or already names the caller as its owner (a replay). The stamp is permanent,
		// so a founder who handed the org over and was removed does not take it back;
		// owners are added by invitation. Any other pre-existing org belongs to another
		// tenant → refuse. So an interrupted founding RESUMES to one org + owner instead
		// of stranding on a permanent 409, and a second identity can never complete,
		// join, or hijack the org.
		if !orgCreated && !(user.Owner == cl.slug && user.IsAdmin) {
			taken := org.Founder != founder
			if !taken {
				m, err := store.GetMembership(ctx, tx, holder, cl.slug)
				if err != nil {
					return &fault{500, "server_error"}
				}
				if m == nil || m.Role != store.RoleOwner {
					if taken, err = store.HasOwner(ctx, tx, cl.slug); err != nil {
						return &fault{500, "server_error"}
					}
				}
			}
			if taken {
				return &fault{409, "the organization \"" + cl.slug + "\" already exists"}
			}
		}

		// A signup's founding moves the account into the org as its admin (changing
		// Owner re-keys the identity; lookups are by (owner, name)). Already-there is a
		// no-op that skips the write. The org's balance starts at zero — usage is
		// pre-paid.
		wasOwner := user.Owner
		if cl.move && (user.Owner != cl.slug || !user.IsAdmin) {
			user.Owner = cl.slug
			user.IsAdmin = true
			user.UpdatedTime = provisionNow()
			if err := user.UpdateCtx(ctx); err != nil {
				return &fault{500, "server_error"}
			}
		}
		if cl.move {
			out.movedFrom = wasOwner
		}

		// Ensure the founder's ONE default key — filed in the org (Owner=slug), so the
		// gateway meters every request under it, and held by the founder, so it speaks
		// for the person who founded the org and for no account standing in between.
		// Its secret is stored as a DIGEST (never plaintext) and revealed exactly once,
		// on the mint that issues it. Idempotent on the row: a replay returns the key's
		// publishable half, never a second key and never the secret again.
		k, err := orm.Get[schema.Key](tx, cl.slug+"/"+keys.DefaultKeyName)
		if err != nil && !errors.Is(err, orm.ErrNotFound) {
			return &fault{500, "server_error"}
		}
		keyCreated := errors.Is(err, orm.ErrNotFound)
		if keyCreated {
			accessKey, secret, mErr := keys.Issue(ctx, tx, cl.slug, holder, keys.DefaultKeyName, keys.DefaultKeyLabel)
			if mErr != nil {
				return &fault{500, "server_error"}
			}
			out.accessKey = accessKey
			out.accessSecret = secret // shown once, on the mint that issues it
		} else {
			out.accessKey = k.AccessKey
		}

		// Record the founder ON the org's roster. It is how a founder who stays where
		// they are owns the org at all: the signed `orgs` claim and the org switch read
		// it. A moved founder is the org's admin by the move as well, but the (User ×
		// Org) relation is what an org's ROSTER is read from (MembershipsByOrg:
		// invitations, team management, the org-switch grant), so without this row a
		// self-service org is born with nobody on it. RoleOwner, not admin: the founder
		// is the org's owner, and EnsureMembership never downgrades, so a later
		// home-org backfill (which would write RoleAdmin) can no longer quietly demote
		// them. Idempotent on the (user, org) pair, so a replay adds nothing.
		if _, err := store.EnsureMembership(ctx, tx, holder, cl.slug, store.RoleOwner); err != nil {
			return &fault{500, "server_error"}
		}
		// The move RE-KEYS the caller (user ids are "<owner>/<name>"), which strands
		// the membership row filed under the OLD id: it names an identity that no
		// longer exists, so the previous org's roster keeps a ghost member forever.
		// Drop it in the same converge that re-keyed the user — one identity, one set
		// of memberships. Idempotent (a missing row reports false, never an error).
		// The grants the caller signed in with name the old id too, so they move
		// with the identity: a refresh after founding renews into the new org
		// instead of answering invalid_grant to the person who just founded it.
		if wasOwner != home {
			if _, err := store.DeleteMembership(ctx, tx, wasOwner+"/"+cl.name, wasOwner); err != nil {
				return &fault{500, "server_error"}
			}
			if err := store.RekeyTokens(ctx, tx, wasOwner+"/"+cl.name, cl.slug+"/"+cl.name); err != nil {
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

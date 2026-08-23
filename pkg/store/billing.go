// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"github.com/hanzoai/account"

	"github.com/hanzoai/iam/pkg/schema"
)

// BillingAccount names the ledger a principal spends from, so nothing downstream
// has to infer it.
//
// account.Payer honours this value above everything else; absent it Payer falls
// back to a SHAPE rule, and that rule makes the signup org special: a member of
// any other org spends the ORG POOL, but a member of "hanzo" gets a PERSONAL
// wallet. The asymmetry is deliberate — every self-signup lands in hanzo, and
// pooling strangers would let a brand-new $0 account spend the platform balance.
//
// A MACHINE has no person, so the personal wallet that rule hands it is a ghost:
// no funding path can name "<signupOrg>/<serviceAccount>" — an admin grant credits
// the pool, a deposit names a real member — so it reads $0 forever while the org's
// balance sits one key away. Hanzo's own first-party identities live in the signup
// org, so each was gated on an unfundable wallet and 402'd against a funded org.
//
// A PERSON who owns or administers their home org holds that org's credit and
// spends the pool too. A plain member gets no claim and still falls through to the
// personal wallet, which is what keeps the free-rider hole shut.
//
// Only the principal's HOME org is ever named: this says where THIS credential
// spends, and one tenant's credential must never name another's ledger.
//
// It is stated in ONE place because the two credentials a principal can present —
// a token and an API key — reach the money path by different paths, and a rule
// copied into each path is a rule that drifts.
func BillingAccount(u *schema.User, refs []schema.OrgRef) string {
	if u == nil || u.Owner == "" {
		return ""
	}
	// IAM's OWN predicate, not account.IsMachine: the fleet disagrees about which
	// User.Type strings name a machine (older copies accept "application" alone),
	// and a service account resolving as a person is exactly the ghost wallet this
	// names a ledger to avoid. IAM writes the type, so IAM reads it.
	if u.Machine() {
		return account.Org(u.Owner).String()
	}
	for _, r := range refs {
		if r.Org != u.Owner {
			continue
		}
		switch r.Role {
		case RoleOwner, RoleAdmin:
			// "org:<slug>" — account.Parse REQUIRES the kind prefix and returns a
			// zero Account without it, which Payer then ignores in favour of its
			// shape rule. A bare slug rides all the way to the gate and is dropped
			// at the last step, so an admin keeps paying from a personal wallet
			// while the pool sits unused.
			return account.Org(u.Owner).String()
		}
	}
	return "" // no claim ⇒ Payer's shape rule decides, unchanged
}

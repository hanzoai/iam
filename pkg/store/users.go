// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/model"
)

// GetMailableUsers lists the users of ONE organization that a non-transactional
// sender (a product announcement, a marketing drip) may lawfully and usefully
// reach: not deleted, not forbidden, and carrying an address. It is the customer
// ROSTER — an embedder resolves an audience against this instead of keeping a
// contact list of its own, so IAM stays the one source of truth for who a
// customer is and there is no second copy to drift.
//
// READ-ONLY BY CONSTRUCTION. There is no user write in this package: a sender
// must never mutate an identity. Rows come back MASKED (schema.User.Mask, the ONE
// redaction contract), so the password digest, access secret, TOTP seed and bearer
// material never cross the embed seam even in-process.
//
// org is REQUIRED — unlike GetProjects, an empty owner is refused rather than
// treated as the unscoped admin view. Owner IS the tenant, so an empty filter
// would return every user of every organization; on this path that is a
// cross-tenant mailing, not a listing. Fail closed instead.
//
// The deleted/forbidden/address predicates are applied in Go, not pushed into the
// query, BECAUSE the flags are `omitempty`: a false value is absent from the
// stored JSON document entirely, so a store-side `isDeleted = false` filter would
// match no row and the roster would come back empty. Only the owner filter —
// the tenancy key, always present and indexed — is pushed down.
func GetMailableUsers(db orm.DB, org string) ([]*model.User, error) {
	if org == "" {
		return nil, errors.New("iam store: organization is required")
	}
	rows, err := orm.TypedQuery[model.User](db).Filter("owner", org).Order("name").GetAll(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]*model.User, 0, len(rows))
	for _, u := range rows {
		if u == nil || u.IsDeleted || u.IsForbidden || u.Email == "" {
			continue
		}
		out = append(out, u.Mask())
	}
	return out, nil
}

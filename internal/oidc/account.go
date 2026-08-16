// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
)

// PUT /v1/iam/account — the ONE place a person edits their own profile.
//
// The subject is ALWAYS the caller. The body names no target, so there is no
// shape of this request that writes somebody else's record — the same property
// PUT /v1/iam/password has, and for the same reason: every other writer of a
// user row is admin-scoped, because internal/authz gates the self clause to GET
// so a regular user cannot carry isAdmin on a full-row write. Widening that
// clause is the escalation it exists to prevent, so self-service lives here
// instead, with the FIELDS it may write named one by one.
//
// A FIXED SET, and its shape is the whole gate. Four scalars, each of them
// display: name, picture, a line about yourself, a link. What is absent is
// absent on purpose and must stay absent:
//
//	owner, name              the principal — renaming is moving a real identity
//	isAdmin, permissions     authority
//	passwordHash, accessKey  credentials
//	email, phone             LOGIN IDENTIFIERS and second-factor destinations.
//	                         Changing where a code is delivered is a credential
//	                         act, and it is only safe when the NEW address has
//	                         proved it can receive one — which is the verification
//	                         flow's job, not a profile save's.
//	properties               the consent record nests inside it (PreferencesKey),
//	                         so a profile write reaching it would let anyone
//	                         answer the data-sharing questions on their own behalf
//
// A field is a POINTER, so an omitted one PRESERVES and an explicit empty one
// CLEARS. A screen that saves one control therefore cannot blank the three it
// did not render, and two screens saving at once do not undo each other.

// accountBody is a profile patch: every field optional, nothing outside the set.
type accountBody struct {
	DisplayName *string `json:"displayName"`
	Avatar      *string `json:"avatar"`
	Bio         *string `json:"bio"`
	Homepage    *string `json:"homepage"`

	// The two credentials a signed-in caller can present, bound from the request
	// headers so this stays a typed op — the portal holds a session cookie, an API
	// client holds a bearer, and resolving only one would take profile editing away
	// from the other.
	Cookie string `json:"-" header:"Cookie"`
	Auth   string `json:"-" header:"Authorization"`
}

// profile is what a profile IS, on the wire: a bounded view of the stored row.
// It is an explicit projection rather than the masked user, so a field added to
// the row later joins this answer only when somebody decides it should.
type profile struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Avatar      string `json:"avatar"`
	Bio         string `json:"bio"`
	Homepage    string `json:"homepage"`
}

// putAccountHandler saves the calling person's own profile — the name they are
// shown by, their picture, a line about themselves and a link.
//
// Only their own: the request names nobody, so it cannot reach another account.
// Send only what you are changing; a field you leave out keeps the value it had,
// and a field you send empty is cleared.
//
// A picture is an https link or an inline image up to 96 KiB, the same value an
// organization's mark is (schema.AvatarRef) — one rule for how a subject appears,
// whether the subject is a person or an organization.
func putAccountHandler(db orm.DB) zip.TypedHandler[accountBody, httpx.Answer] {
	return func(ctx context.Context, in *accountBody) (*httpx.Answer, error) {
		owner, name, ok := callerFrom(ctx, db, sessionCookie(in.Cookie), httpx.BearerValue(in.Auth))
		if !ok {
			return httpx.Bad(400, "please sign in first", CodeLoginRequired), nil
		}
		// Validated BEFORE the write, so a picture this service will not store is a
		// refusal rather than a half-saved profile.
		var image string
		if in.Avatar != nil {
			ref, err := schema.AvatarRef(*in.Avatar)
			if err != nil {
				return httpx.Bad(400, err.Error(), ""), nil
			}
			image = ref
		}

		saved, err := updateUser(ctx, db, owner, name, func(_ orm.DB, u *schema.User) error {
			if in.DisplayName != nil {
				u.DisplayName = *in.DisplayName
			}
			if in.Avatar != nil {
				u.Avatar = image
			}
			if in.Bio != nil {
				u.Bio = *in.Bio
			}
			if in.Homepage != nil {
				u.Homepage = *in.Homepage
			}
			return nil
		})
		if err != nil {
			return httpx.Bad(400, "the profile could not be saved", ""), nil
		}
		return httpx.Good(profile{
			Owner:       saved.Owner,
			Name:        saved.Name,
			DisplayName: saved.DisplayName,
			Avatar:      saved.Avatar,
			Bio:         saved.Bio,
			Homepage:    saved.Homepage,
		}), nil
	}
}

// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package social

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/idp"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// The link law (HIP-0111 §7). An account may be selected by a third-party
// identity through exactly two keys, and no others:
//
//	(a) the provider SUBJECT already stored on the account's link column — the
//	    provider's own opaque user id, which the account holder cannot choose
//	    and an attacker cannot claim; or
//	(b) an email address that BOTH sides assert is verified — the provider
//	    asserts it (idp.Identity.Verified) and the local row asserts it
//	    (schema.User.EmailVerified) — and only when the application enables
//	    email linking.
//
// Every other collision creates a NEW account. A username never links: an
// attacker chooses their own GitHub login, so a login equal to a victim's
// username would hand over the victim's account — v1 does exactly this,
// unconditionally (controllers/auth.go:1084-1090). A phone never links, for the
// same reason. Both sides of (b) must be verified: linking a provider-verified
// address onto an unverified local row lets an attacker pre-register the
// victim's address with a password of their choosing and inherit the account
// when the real owner first signs in with the provider.

// ErrLinked is returned when a link column already names a different subject.
// A second subject never overwrites the first — that would be a takeover with
// extra steps.
var ErrLinked = errors.New("social: the account is already linked to a different provider account")

// link is one connector's column on the user row: what to filter by, how to
// read it, how to write it.
//
// The field name is what orm filters by, and it must be the json tag with its
// first letter raised — that is the mapping orm inverts (db.ToJSONFieldName →
// LowercaseFirst), and a name that does not round-trip through it matches
// NOTHING while reporting no error. That is why the user column is `Github` and
// not v1's `GitHub`, which would map to `gitHub` and never find the `github` it
// wrote (schema/user.go).
type link struct {
	field string
	read  func(*schema.User) string
	write func(*schema.User, string)
}

// links is the ONE table of linkable providers: the type iam2 knows, spelled
// the way the provider spells it, mapped to its column. Explicit and total —
// v1 instead reflects the provider TYPE onto a field name, and because the type
// is "GitLab" while the column is `Gitlab`, it reads back the literal
// "<invalid Value>" for every GitLab account and never notices
// (object/user_util.go:292-296). One entry carries all three capabilities, so a
// connector cannot be half-wired; an unknown type is a hard miss, never a
// silent one.
var links = map[string]link{
	"GitHub": {"Github", func(u *schema.User) string { return u.Github }, func(u *schema.User, v string) { u.Github = v }},
	"Google": {"Google", func(u *schema.User) string { return u.Google }, func(u *schema.User, v string) { u.Google = v }},
	"GitLab": {"Gitlab", func(u *schema.User) string { return u.Gitlab }, func(u *schema.User, v string) { u.Gitlab = v }},
}

// subject returns the provider subject currently linked on u, and whether the
// provider type is one iam2 links at all.
func subject(u *schema.User, kind string) (string, bool) {
	l, ok := links[kind]
	if !ok {
		return "", false
	}
	return l.read(u), true
}

// byLink finds the account in org already linked to this provider subject —
// key (a), the unforgeable one.
func byLink(ctx context.Context, db orm.DB, org, kind, subject string) (*schema.User, error) {
	l, ok := links[kind]
	if !ok || subject == "" {
		return nil, nil
	}
	u, err := orm.TypedQuery[schema.User](db).
		Filter("Owner=", org).Filter(l.field+"=", subject).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u != nil && (u.IsDeleted || u.IsForbidden) {
		return nil, nil // a revoked account is never signed in to
	}
	return u, nil
}

// resolve returns the account this identity may sign in as, or nil to signal
// sign-up. It is the whole law: keys (a) and (b) above, in that order, and
// nothing else.
func resolve(ctx context.Context, db orm.DB, org, kind string, app *schema.Application, id *idp.Identity) (*schema.User, error) {
	// (a) The subject already on file. Unforgeable, so it needs no further gate.
	if u, err := byLink(ctx, db, org, kind, id.Subject); u != nil || err != nil {
		return u, err
	}
	// (b) A verified email, on both sides, when the application allows it.
	if !app.EnableLinkWithEmail || !id.Verified || id.Email == "" {
		return nil, nil
	}
	u, err := store.GetUserByEmail(ctx, db, org, strings.ToLower(id.Email))
	if err != nil || u == nil {
		return nil, err
	}
	if !u.EmailVerified {
		return nil, nil // the local address is unproven: it may be a squat
	}
	if u.IsDeleted || u.IsForbidden {
		return nil, nil
	}
	return u, nil
}

// attach records on an existing account what the provider just said about it:
// the subject, so the next sign-in resolves by key (a), and any descriptive
// field the account left empty. An account already linked to a DIFFERENT
// subject is refused — the first link stands until unlink removes it.
//
// Only the empty descriptive fields are filled, so a provider can never
// overwrite what the account holder set, and Email/EmailVerified are never
// touched: on an existing account those are authentication inputs, not profile
// data, and rewriting them would rewrite what may link to it next time.
//
// v1 additionally stashes the upstream access and refresh tokens on the row
// (object/user_util.go:345-358); iam2 does not. Nothing reads them, and a
// third-party bearer at rest with no reader is a liability, not a feature.
func attach(ctx context.Context, db orm.DB, u *schema.User, kind string, id *idp.Identity) error {
	l, ok := links[kind]
	if !ok {
		return idp.ErrKind
	}
	if cur := l.read(u); cur != "" {
		if cur != id.Subject {
			return ErrLinked
		}
		return nil
	}
	l.write(u, id.Subject)
	fill(u, id)
	return save(ctx, db, u)
}

// save writes a loaded account back, preserving the orm identity it was read
// with. The ONE writer of a link column change.
func save(ctx context.Context, db orm.DB, u *schema.User) error {
	u.Init(db)
	u.UpdatedTime = time.Now().UTC().Format(time.RFC3339)
	return u.UpdateCtx(ctx)
}

// fill sets the descriptive fields an account left empty.
func fill(u *schema.User, id *idp.Identity) {
	if u.DisplayName == "" {
		u.DisplayName = display(id)
	}
	if u.Avatar == "" {
		u.Avatar = id.Avatar
	}
}

// display is the name to show for an identity: what the provider calls it, else
// its handle, else its subject — never empty.
func display(id *idp.Identity) string {
	return or(id.Display, or(id.Username, id.Subject))
}

// or returns v when set, else fallback.
func or(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

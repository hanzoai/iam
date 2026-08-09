// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PUT /v1/iam/password — the ONE place a person's own password is written.
//
// It closes a hole with no bottom: nothing anywhere consumed a verification code
// and set a credential, so /v1/iam/verification-codes minted and delivered a code
// that no endpoint could redeem into a password. A locked-out person could not
// finish a reset by any route, and a signed-in person could not rotate their own
// password either — every writer (users update, admin upsert, SCIM) is
// admin-scoped, because internal/authz deliberately gates the self clause to GET
// so a regular user cannot carry isAdmin on a full-row write. Widening that
// clause is the privilege escalation the comment there guards against, so the
// self path belongs here instead: one endpoint, self-scoped, with the ONE field
// it may write.
//
// Two proofs of the same person, one write site:
//
//   - A SIGNED-IN caller proves it with the password being replaced. The subject
//     is ALWAYS the caller (callerOf), exactly as PUT /v1/iam/consent does it —
//     the body never names a target on this arm, so there is no shape in which
//     this writes somebody else's credential.
//   - A LOCKED-OUT caller has no session, which is the whole point, so it names
//     the account and proves it with a code delivered to that account's own
//     address. The code is spent by [otp.Consume], which is bound to the account
//     it was minted for.
//
// It is not a second authentication scheme and must never become one. Nothing
// here mints a session, a token or an authorization code: a person who lands a
// reset then signs in through /v1/iam/login like anybody else, second factor
// included. The old-password proof runs through users.Authenticate — the single
// human-credential check — so the account lockout applies to a rotation exactly
// as it applies to a login.
const PathPassword = "/v1/iam/password"

// errPasswordCode is the ONE refusal for every way the code arm can fail:
// unknown account, wrong or expired or spent or foreign code, nothing able to
// deliver. They collapse to one answer because telling them apart answers "does
// this address have an account" to anyone who asks.
const errPasswordCode = "the code is incorrect or has expired"

// passwordBody is the wire shape. Exactly one proof may be present, and which
// one it is selects the arm.
type passwordBody struct {
	// The account being recovered, for a caller who cannot be signed in. Read on
	// the CODE arm only — a signed-in caller is resolved from its own session or
	// token, never from these.
	Organization string `json:"organization"`
	Username     string `json:"username"` // email, username OR phone
	// Code is the one-time code delivered to the account's own address.
	Code string `json:"code"`
	// OldPassword is the credential being replaced, the proof a signed-in caller
	// gives instead of a code.
	OldPassword string `json:"oldPassword"`
	// Password is the new credential. It must satisfy the platform floor and the
	// organization's own complexity options.
	Password string `json:"password"`

	// The two credentials a signed-in caller can present, bound from the request
	// headers so this stays a typed op. `json:"-"` keeps them off the body and out
	// of the query string, so the header is the only way to present either.
	//
	// Both, because the two arms of this endpoint serve two callers: the portal
	// holds a session cookie, an API client holds a bearer. Resolving only one of
	// them would silently take password change away from the other.
	Cookie string `json:"-" header:"Cookie"`
	Auth   string `json:"-" header:"Authorization"`
}

// sessionCookie is the session value carried by a raw `Cookie` header, or "".
// A typed op is handed the header rather than the request, so the parse that
// fiber's c.Cookies does lives here instead.
func sessionCookie(header string) string {
	for _, c := range readCookies(header) {
		if c.Name == sessions.CookieName {
			return c.Value
		}
	}
	return ""
}

// readCookies parses a Cookie header with the standard library's own rules, so a
// quoted value or an unusual separator is read exactly as net/http reads it.
func readCookies(header string) []*http.Cookie {
	if header == "" {
		return nil
	}
	return (&http.Request{Header: http.Header{"Cookie": []string{header}}}).Cookies()
}

// putPasswordHandler replaces the calling person's password. Only their own —
// there is no shape of this request that writes somebody else's.
//
// Prove who you are with the password you are replacing, or — when you cannot
// sign in at all — with a code sent to the address the account already holds.
// Exactly one of the two: a request carrying both proves nothing more than
// either, and answering it would mean deciding which one mattered.
//
// A reset also clears the account lockout, in the SAME transaction as the
// digest. Replacing a credential retires the run of guesses against the old one,
// and without this a person who reset a forgotten password was still refused for
// up to fifteen more minutes — with the brand-new password they had just chosen.
func putPasswordHandler(db orm.DB) zip.TypedHandler[passwordBody, httpx.Answer] {
	return func(ctx context.Context, in *passwordBody) (*httpx.Answer, error) {
		if in.Password == "" {
			return httpx.Bad(400, "password cannot be empty", ""), nil
		}
		if (in.Code == "") == (in.OldPassword == "") {
			return httpx.Bad(400, "send either the current password or a verification code, not both", ""), nil
		}

		var user *schema.User
		if in.Code != "" {
			var err error
			if user, err = codeSubject(ctx, db, *in); err != nil {
				return httpx.Bad(400, err.Error(), ""), nil
			}
			if user == nil {
				return httpx.Bad(400, errPasswordCode, ""), nil
			}
		} else {
			owner, name, ok := callerFrom(ctx, db, sessionCookie(in.Cookie), httpx.BearerValue(in.Auth))
			if !ok {
				return httpx.Bad(400, "please sign in first", CodeLoginRequired), nil
			}
			var err error
			if user, err = store.GetUserByName(ctx, db, owner, name); err != nil {
				return httpx.Bad(400, err.Error(), ""), nil
			}
			if user == nil {
				return httpx.Bad(400, "the user does not exist", ""), nil
			}
			// The one human-credential check, so a rotation is subject to the same
			// lockout as a login and a correct old password clears the running count.
			ok, locked := users.Authenticate(ctx, db, user, in.OldPassword,
				loginOrgPasswordType(ctx, db, user.Owner), nowFunc())
			if locked {
				return httpx.Bad(400, "too many failed attempts; the account is temporarily locked", ""), nil
			}
			if !ok {
				return httpx.Bad(400, "the current password is incorrect", ""), nil
			}
		}

		// Complexity is the org's, floored by the platform's — the same rule signup
		// enforces, from the same function, so a password that could not have been
		// registered cannot be arrived at by resetting either.
		org, err := store.GetOrganizationByName(ctx, db, user.Owner)
		if err != nil {
			return httpx.Bad(400, err.Error(), ""), nil
		}
		var options []string
		if org != nil {
			options = org.PasswordOptions
		}
		if msg := passwordPolicyError(options, in.Password); msg != "" {
			return httpx.Bad(400, msg, ""), nil
		}
		hash, err := cred.Hash(in.Password)
		if err != nil {
			return httpx.Bad(400, "server_error", ""), nil
		}

		// One row-locked write for the digest AND the lockout, through the same seam
		// every other pre-authentication user-row write uses. Clearing the counter
		// here rather than in users.Update is deliberate: a full-row admin profile
		// edit must keep carrying it forward (F-6), because an omitted counter there
		// would silently unlock a locked account mid-attack. What retires the run of
		// guesses is replacing the credential they were aimed at, which is this.
		if _, err := updateUser(ctx, db, user.Owner, user.Name, func(_ orm.DB, u *schema.User) error {
			u.PasswordHash = hash
			u.PasswordType = cred.TypeArgon2id
			u.PasswordSalt = ""
			u.SigninWrongTimes = 0
			u.LastSigninWrongTime = ""
			u.UpdatedTime = provisionNow()
			return nil
		}); err != nil {
			return httpx.Bad(400, err.Error(), ""), nil
		}
		return httpx.Good(nil), nil
	}
}

// codeSubject resolves the account a code-proved reset is for, or nil when the
// code does not prove one. Every refusal is nil, never a distinguishable error.
//
// Delivery must be configured, for the same reason codeLogin requires it: a
// process that cannot send a code cannot have sent the one it is being asked to
// trust.
func codeSubject(ctx context.Context, db orm.DB, in passwordBody) (*schema.User, error) {
	if !otp.DeliveryConfigured() || in.Organization == "" || in.Username == "" {
		return nil, nil
	}
	// The SAME resolution login uses, so the account a code recovers is the account
	// that identifier signs in as — name first, then email, then phone.
	user, err := resolveLoginUser(ctx, db, in.Organization, in.Username)
	if err != nil {
		return nil, err
	}
	ok, err := otp.Consume(ctx, db, user, in.Username, in.Code, nowFunc())
	if err != nil || !ok {
		return nil, err
	}
	return user, nil
}

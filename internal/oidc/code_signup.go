// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// SignupRequired is the answer to a code sign-in whose address proved live but
// holds no account: the person must accept the terms and ask for the account to
// be made. It sits beside NextMfa and RequiredMfa as a non-error `data` value.
//
// It is revealed only to someone who proved control of the address, which is the
// one caller entitled to learn the address has no account. A wrong, spent or
// expired code still gets the opaque refusal every other miss gets.
const SignupRequired = "SignupRequired"

// PathTerms records the calling person's acceptance of the Terms of Service and
// the Acceptable Use Policy. Self-scoped, like PathConsent: the target is always
// the caller.
const PathTerms = "/v1/iam/terms"

// Accepted is the method a code sign-up records. A signed-in acceptance records
// methodSignedIn.
const (
	methodEmailCode = "email-code"
	methodSignedIn  = "signed-in"
)

// termsVersion bounds and shapes a document version: a label, not free text.
var termsVersion = regexp.MustCompile(`^[0-9A-Za-z._-]{1,64}$`)

var errCodeRefused = "the code is incorrect or has expired"

// codeSignup answers a code sign-in that resolved no account.
//
// Without Create it only reports whether the address may sign up: SignupRequired
// when the application registers strangers and the code is live for the address,
// the opaque refusal otherwise. The code is NOT spent, so the same code then
// creates the account.
//
// With Create and the accepted versions it makes the account — passwordless, the
// address proven, never admin, founded exactly as a federated sign-up is — spends
// the code, records the acceptance, and finishes through afterFirstFactor, the
// one tail every first factor reaches.
func codeSignup(c *zip.Ctx, db orm.DB, f loginForm) error {
	ctx := c.Context()
	app, err := store.GetApplicationByClientId(ctx, db, f.ClientId)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	// The code was filed under the application's org, so only a request naming it
	// can be about this code. A phone has no account name to derive here.
	if !sendsCodes(app) || !app.EnableSignUp || !Registers(app, app.Organization) ||
		f.Organization != app.Organization || store.LooksLikePhone(f.Username) {
		return httpx.Err(c, errCodeRefused)
	}
	now := nowFunc()

	if !f.Create {
		ok, err := otp.Check(ctx, db, app.Organization, f.Username, f.Code, now)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if !ok {
			return httpx.Err(c, errCodeRefused)
		}
		return httpx.Ok(c, SignupRequired)
	}

	if !termsVersion.MatchString(f.Terms) || !termsVersion.MatchString(f.AUP) {
		return httpx.Err(c, "the terms and the acceptable use policy must be accepted")
	}

	// A row that appeared since the first request holds the address now. Looked up
	// before the code is spent, so the person keeps it and signs in with it.
	held, err := resolveLoginUser(ctx, db, app.Organization, f.Username, false)
	if err != nil {
		return httpx.Err(c, "sign-in is unavailable")
	}
	if held != nil {
		return httpx.Err(c, "an account already holds this address; sign in instead")
	}

	ok, err := otp.Prove(ctx, db, app.Organization, f.Username, f.Code, now)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if !ok {
		return httpx.Err(c, errCodeRefused)
	}

	created, err := createWithCode(ctx, db, app, f.Username, &schema.Terms{
		Terms:  f.Terms,
		AUP:    f.AUP,
		Time:   now.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Method: methodEmailCode,
		IP:     httpx.ClientIP(c),
	})
	if err != nil {
		var ze *zip.HTTPError
		if errors.As(err, &ze) && ze.Status == http.StatusConflict {
			return httpx.Err(c, "an account already holds this address; sign in instead")
		}
		return httpx.Err(c, err.Error())
	}
	return afterFirstFactor(c, db, created, f, factor.Email)
}

// createWithCode makes the passwordless account an address proved by code is owed.
// It is provisionFederatedUser with the address proof coming from IAM's own code
// rather than a provider: no digest, verified address, normal user, never admin,
// in the application's org (never a reserved one — Registers refused that above),
// founded into an org of its own where the application founds one.
func createWithCode(ctx context.Context, db orm.DB, app *schema.Application, address string, terms *schema.Terms) (*schema.User, error) {
	org := app.Organization
	name, err := allocateName(ctx, db, org, address, "")
	if err != nil {
		return nil, err
	}
	created, err := users.New(db).Create(ctx, &users.CreateInput{
		User: schema.User{
			Owner:          org,
			Name:           name,
			DisplayName:    name,
			Email:          address,
			RegisterType:   "Email Code",
			RegisterSource: org + "/" + app.Name,
		},
		Type:          "normal-user",
		EmailVerified: true,
		Application:   app.Name,
		Terms:         terms,
	})
	if err != nil {
		return nil, err
	}
	return Charter(ctx, db, app, created)
}

// termsBody is the wire shape of PUT /v1/iam/terms. The credentials ride the
// request headers so this stays a typed op, and `json:"-"` keeps them off the body.
type termsBody struct {
	Terms     string `json:"terms" url:"-"`
	AUP       string `json:"aup" url:"-"`
	Cookie    string `json:"-" header:"Cookie"`
	Auth      string `json:"-" header:"Authorization"`
	Forwarded string `json:"-" header:"X-Forwarded-For"`
}

// putTermsHandler records that the signed-in caller accepted the terms and the
// acceptable use policy, at the versions named. It is how a person who arrived by
// a social provider, whose account the callback already made, records the same
// acceptance a code sign-up records at creation. Only the caller's own row is
// reachable.
func putTermsHandler(db orm.DB) zip.TypedHandler[termsBody, httpx.Answer] {
	return func(ctx context.Context, in *termsBody) (*httpx.Answer, error) {
		owner, name, ok := callerFrom(ctx, db, sessionCookie(in.Cookie), httpx.BearerValue(in.Auth))
		if !ok {
			return httpx.Bad(400, "please sign in first", CodeLoginRequired), nil
		}
		if !termsVersion.MatchString(in.Terms) || !termsVersion.MatchString(in.AUP) {
			return httpx.Bad(400, "the terms and the acceptable use policy must be accepted", ""), nil
		}
		var out schema.Terms
		if _, err := updateUser(ctx, db, owner, name, func(_ orm.DB, u *schema.User) error {
			if prior, ok := u.TermsAccepted(); ok && prior.Terms == in.Terms && prior.AUP == in.AUP {
				out = prior // accepted already at these versions: the first record stands
				return nil
			}
			out = schema.Terms{
				Terms:  in.Terms,
				AUP:    in.AUP,
				Time:   nowFunc().UTC().Format("2006-01-02T15:04:05Z07:00"),
				Method: methodSignedIn,
				IP:     in.Forwarded,
			}
			u.UpdatedTime = provisionNow()
			return u.SetTerms(&out)
		}); err != nil {
			return httpx.Bad(400, err.Error(), ""), nil
		}
		return httpx.Good(out), nil
	}
}

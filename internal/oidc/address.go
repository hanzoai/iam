// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PUT /v1/iam/address — the ONE way a person adds a sign-in address to their own
// account: an email address or a phone number, proved by a code sent to it.
//
// PUT /v1/iam/account refuses both fields, because an address is a login
// identifier and a second-factor destination, and writing one is only safe once
// the NEW address has proved it can receive a code. This is that proof. It is what
// lets an account that began with no address at all — a wallet, an agent signing
// up headlessly — be signed in to later by a person, by email or by text, as the
// SAME account.
//
// The subject is ALWAYS the caller (callerFrom: a session cookie spendable by this
// write, or a bearer the person holds themselves). The body names no account, so
// no shape of it writes another one, and a bearer someone else acts through — an
// impersonation, a delegation — resolves nobody here.
//
// The proof is the code POST /v1/iam/verification-codes sends to an address no
// account holds: filed for nobody, under the application's org (otp.Prove). After
// this write, sign-in at that application by the address resolves exactly this
// account, which is why everything between the caller and the write is about
// that one fact:
//
//   - the application must sign the caller in at all — the caller lives in its
//     org or registered there (store.RegisteredIn), the same reach sign-in has;
//   - an address any OTHER account would be resolved by at that application
//     (resolveLoginUser, the sign-in's own resolution) is refused before the code
//     is spent, in the words a wrong code gets. A distinct answer would tell any
//     account holder which addresses have accounts;
//   - it ADDS and never REPLACES. An account that already signs in with an email
//     (or a phone) keeps it, and a different one is refused: moving where a
//     person's codes are delivered retires the address that recovers the account,
//     and doing that is a separate owner decision, not this endpoint.
//
// An email lands verified, because the code just proved it. The change is audited
// on the same transaction as the write (schema.ActionAddress), naming which field
// and which application, never the address or the code.
const PathAddress = "/v1/iam/address"

// errAddressSet is a write that found the field already holding another address.
var errAddressSet = errors.New("address already set")

// refuseSet answers an add whose field already holds another address.
func refuseSet(channel string) *httpx.Answer {
	what := "an email address"
	if channel == otp.Phone {
		what = "a phone number"
	}
	return httpx.Bad(http.StatusConflict, "this account already signs in with "+what+"; an address is added here, never replaced", "")
}

// addressBody is the wire shape: the application, the address and its code, each
// `url:"-"` so the body is the only place any of them can be stated.
type addressBody struct {
	// ClientId is the application the address will sign in at — the one whose
	// applicationId the code was sent under.
	ClientId string `json:"clientId" url:"-"`
	// Address is the email address or phone number being added.
	Address string `json:"address" url:"-"`
	// Code is the one-time code sent to Address.
	Code string `json:"code" url:"-"`

	// The two credentials a signed-in caller can present, bound from the request
	// headers so this stays a typed op. Site, Origin, Host and Type are what the
	// cookie is judged by (sessions.Forgeable).
	Cookie string `json:"-" header:"Cookie"`
	Auth   string `json:"-" header:"Authorization"`
	Site   string `json:"-" header:"Sec-Fetch-Site"`
	Origin string `json:"-" header:"Origin"`
	Host   string `json:"-" header:"Host"`
	Type   string `json:"-" header:"Content-Type"`
}

// asker is what this PUT presents to say who is asking.
func (in *addressBody) asker() asker {
	return asker{Method: http.MethodPut, Cookie: sessionCookie(in.Cookie), Site: in.Site, Origin: in.Origin, Host: in.Host, Type: in.Type, Bearer: httpx.BearerValue(in.Auth)}
}

// addresses is the answer: the account and the two addresses it signs in with.
type addresses struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

func addressesOf(u *schema.User) addresses {
	return addresses{Owner: u.Owner, Name: u.Name, Email: u.Email, Phone: u.Phone}
}

// addressOf reads s as a sign-in address: the channel it is reached over and the
// one form it is stored in. An email is a bare address (no display name, no
// brackets), lowercased; a phone is its digits with any leading "+". Anything else
// is no address.
func addressOf(s string) (channel, stored string) {
	if a, err := mail.ParseAddress(s); err == nil && a.Name == "" && a.Address == s {
		return otp.Email, store.NormalizeEmail(s)
	}
	if store.LooksLikePhone(s) {
		return otp.Phone, store.NormalizePhone(s)
	}
	return "", ""
}

// kept is the address the account keeps for channel, in its stored form.
func kept(u *schema.User, channel string) string {
	if channel == otp.Email {
		return store.NormalizeEmail(u.Email)
	}
	return store.NormalizePhone(u.Phone)
}

// putAddressHandler adds an email address or a phone number to the calling
// person's own account, so they can sign in with it — by a code sent there, or
// to recover a password.
//
// First ask POST /v1/iam/verification-codes to send a code to the new address,
// with the applicationId of the application you sign in at, then send that
// application's clientId, the address and the code here. Only the caller's own
// account is written; the request names nobody.
//
// It adds and never replaces: an account that already has an email keeps it, and
// asking again with the same address answers ok. An address another account at
// that application already signs in with is refused with the same words a wrong
// code gets.
func putAddressHandler(db orm.DB) zip.TypedHandler[addressBody, httpx.Answer] {
	return func(ctx context.Context, in *addressBody) (*httpx.Answer, error) {
		owner, name, err := callerFrom(ctx, db, in.asker())
		if err != nil {
			return callerAnswer(err), nil
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil || user == nil {
			return httpx.Bad(400, errSignedOut.Error(), CodeLoginRequired), nil
		}
		if user.Machine() {
			return httpx.Bad(http.StatusForbidden, "a machine account signs in with its key, never an address", ""), nil
		}
		raw := strings.TrimSpace(in.Address)
		channel, address := addressOf(raw)
		switch {
		case in.ClientId == "":
			return httpx.Bad(400, "clientId is required", ""), nil
		case channel == "":
			return httpx.Bad(400, "the address must be an email address or a phone number", ""), nil
		}

		app, err := store.GetApplicationByClientId(ctx, db, in.ClientId)
		if err != nil {
			return httpx.Bad(400, "the address could not be added", ""), nil
		}
		if app == nil {
			return httpx.Bad(400, "the application does not exist", ""), nil
		}
		if user.Owner != app.Organization {
			reached, err := store.RegisteredIn(ctx, db, app.Organization, user)
			if err != nil {
				return httpx.Bad(400, "the address could not be added", ""), nil
			}
			if !reached {
				return httpx.Bad(http.StatusForbidden, "this application does not sign this account in", ""), nil
			}
		}

		switch current := kept(user, channel); {
		case current == address:
			return httpx.Good(addressesOf(user)), nil
		case current != "":
			return refuseSet(channel), nil
		case in.Code == "":
			return httpx.Bad(400, "the code sent to the address is required", ""), nil
		}

		// Whoever sign-in at this application would resolve by the address now. Asked
		// before the code is spent, and answered as a wrong code is: the caller learns
		// nothing about who holds an address.
		other, err := resolveLoginUser(ctx, db, app.Organization, address, app.IsShared)
		switch {
		case errors.Is(err, store.ErrEmailAmbiguous), errors.Is(err, store.ErrPhoneAmbiguous), errors.Is(err, store.ErrMemberAmbiguous):
			return httpx.Bad(400, errCodeRefused, ""), nil
		case err != nil:
			return httpx.Bad(400, "the address could not be added", ""), nil
		case other != nil && (other.Owner != user.Owner || other.Name != user.Name):
			return httpx.Bad(400, errCodeRefused, ""), nil
		}

		// A process that cannot send a code cannot have sent this one.
		if !otp.DeliveryConfigured() {
			return httpx.Bad(400, errCodeRefused, ""), nil
		}
		ok, err := otp.Prove(ctx, db, app.Organization, raw, in.Code, nowFunc())
		if err != nil {
			return httpx.Bad(400, "the address could not be added", ""), nil
		}
		if !ok {
			return httpx.Bad(400, errCodeRefused, ""), nil
		}

		object, _ := json.Marshal(map[string]string{"field": channel, "client": app.ClientId})
		saved, err := updateUser(ctx, db, user.Owner, user.Name, func(tx orm.DB, u *schema.User) error {
			// Re-read under the row lock: a concurrent add of another address must not
			// be replaced by this one.
			if current := kept(u, channel); current != "" && current != address {
				return errAddressSet
			}
			if channel == otp.Email {
				u.Email = address
				u.EmailVerified = true
			} else {
				u.Phone = address
			}
			u.UpdatedTime = provisionNow()
			return store.Append(ctx, tx, &schema.AuditLog{
				Owner:        u.Owner,
				Organization: u.Owner,
				User:         u.Owner + "/" + u.Name,
				Action:       schema.ActionAddress,
				Object:       string(object),
				Method:       http.MethodPut,
				RequestUri:   PathAddress,
				StatusCode:   200,
			})
		})
		if errors.Is(err, errAddressSet) {
			return refuseSet(channel), nil
		}
		if err != nil {
			return httpx.Bad(400, "the address could not be added", ""), nil
		}
		return httpx.Good(addressesOf(saved)), nil
	}
}

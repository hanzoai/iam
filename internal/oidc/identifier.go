// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/store"
)

// PathAuthIdentifier answers the first step of an identifier-first sign-in: does
// an account hold this address at this application, and can it sign in with a
// password. A screen asks it before it asks for anything else, so a new person is
// shown Create account and a returning one their password or a code.
const PathAuthIdentifier = "/v1/iam/auth/identifier"

// identifierBody is the address a sign-in screen asks about, and the application
// it signs in to. The client address rides the headers, for the throttle.
type identifierBody struct {
	// ClientId is the application's OAuth client id.
	ClientId string `json:"clientId" url:"-"`
	// Identifier is the email address the person typed.
	Identifier string `json:"identifier" url:"-"`
	Connecting string `json:"-" header:"CF-Connecting-IP"`
	Forwarded  string `json:"-" header:"X-Forwarded-For"`
}

// identity is the answer: whether an account holds the address, and whether that
// account has a password this application accepts.
type identity struct {
	// Account is true when an account holds the address at this application.
	Account bool `json:"account"`
	// Password is true when that account can sign in with a password here.
	Password bool `json:"password"`
}

// The answer says whether an address has an account, which this application's
// signup already says to anyone holding a password the org accepts. It is asked
// at a person's pace: a few addresses a minute. More than identifierLimit from
// one client inside identifierWindow is a list being walked, and is refused.
//
// A client is an address the edge reports, and an edge can be lied to, so the
// whole process also answers at most identifierCeiling in a window: past it the
// screen falls back to a code, which serves a new address and a known one alike.
// Each replica counts for itself, so N replicas answer up to N times either bound,
// unless the host installs a count its replicas share (Admit).
const (
	identifierLimit   = 20
	identifierCeiling = 10_000
	identifierWindow  = 10 * time.Minute
	// identifierClients bounds the clients counted at once. Past it a client not
	// already counted is refused until the sweep frees room.
	identifierClients = 100_000
)

type tally struct {
	start time.Time
	n     int
}

// tallies counts each client's questions, and all of them, in their windows.
var tallies = struct {
	sync.Mutex
	by    map[netip.Addr]*tally
	all   tally
	swept time.Time
}{by: map[netip.Addr]*tally{}}

// Admit, when set, decides in place of this process's own count. A host whose
// replicas share a store installs one (server.SetIdentifierAdmit), so between them
// they answer identifierLimit per client and identifierCeiling in all, once. It is
// handed the client and both bounds, and charges what it admits. It is set before
// the server serves and never changed.
var Admit func(client string, limit, ceiling int, window time.Duration) bool

// admitted spends one question from client on the host's count when it installed
// one, else on this process's.
func admitted(client netip.Addr, now time.Time) bool {
	if f := Admit; f != nil {
		return f(client.String(), identifierLimit, identifierCeiling, identifierWindow)
	}
	return admit(client, now)
}

// admit spends one of client's questions, and one of the process's, in the window
// now falls in, or refuses.
func admit(client netip.Addr, now time.Time) bool {
	tallies.Lock()
	defer tallies.Unlock()
	if now.Sub(tallies.swept) >= identifierWindow {
		for k, w := range tallies.by {
			if now.Sub(w.start) >= identifierWindow {
				delete(tallies.by, k)
			}
		}
		tallies.swept = now
	}
	if now.Sub(tallies.all.start) >= identifierWindow {
		tallies.all = tally{start: now}
	}
	if tallies.all.n >= identifierCeiling {
		return false
	}
	w := tallies.by[client]
	switch {
	case w == nil && len(tallies.by) >= identifierClients:
		return false
	case w == nil || now.Sub(w.start) >= identifierWindow:
		tallies.by[client] = &tally{start: now, n: 1}
	case w.n >= identifierLimit:
		return false
	default:
		w.n++
	}
	tallies.all.n++
	return true
}

// client is who is asking: the address the edge saw connect, else the last
// forwarded hop, which the nearest proxy wrote. An IPv6 client holds a /64, so it
// is counted as one. Anything that is not an address is the zero client, which
// every such request shares.
func (in *identifierBody) client() netip.Addr {
	raw := strings.TrimSpace(in.Connecting)
	if raw == "" {
		hops := strings.Split(in.Forwarded, ",")
		raw = strings.TrimSpace(hops[len(hops)-1])
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}
	}
	ip = ip.Unmap()
	if ip.Is6() {
		ip = netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

// authIdentifier answers whether an account holds an email address at an
// application, and whether that account signs in with a password. Only an
// application that registers strangers answers, since its signup says as much
// already. The address is resolved exactly as sign-in resolves it, so the screen
// and the sign-in cannot disagree. A client asking faster than a person types is
// refused with 429.
func authIdentifier(db orm.DB) zip.TypedHandler[identifierBody, httpx.Answer] {
	return func(ctx context.Context, in *identifierBody) (*httpx.Answer, error) {
		address := strings.TrimSpace(in.Identifier)
		if in.ClientId == "" || !strings.Contains(address, "@") {
			return httpx.Bad(400, "clientId and an email address are required", ""), nil
		}
		if !admitted(in.client(), nowFunc()) {
			return httpx.Bad(429, "too many addresses looked up; try again in a few minutes", ""), nil
		}
		app, err := store.GetApplicationByClientId(ctx, db, in.ClientId)
		if err != nil {
			return httpx.Bad(400, err.Error(), ""), nil
		}
		// The same gate a code signup passes (codeSignup): an application closed to
		// strangers, or one in a reserved org, says nothing about who it holds.
		if app == nil || !app.EnableSignUp || !Registers(app, app.Organization) {
			return httpx.Bad(400, "the application does not look up addresses", ""), nil
		}
		// The login handler's resolution: the application's org, and its roster
		// when the application is shared (servesMembers).
		user, err := resolveLoginUser(ctx, db, app.Organization, address, app.IsShared)
		switch {
		case errors.Is(err, store.ErrEmailAmbiguous), errors.Is(err, store.ErrMemberAmbiguous):
			// Taken, as signup reads it; which account holds it is not said.
			return httpx.Good(identity{Account: true}), nil
		case err != nil:
			return httpx.Bad(400, "sign-in is unavailable", ""), nil
		case user == nil:
			return httpx.Good(identity{}), nil
		}
		return httpx.Good(identity{Account: true, Password: app.EnablePassword && user.PasswordHash != ""}), nil
	}
}

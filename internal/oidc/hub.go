// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"sort"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The ACCOUNT HUB: the one record of everywhere this browser is signed in.
//
// One human holds several identities — z@hanzo.ai billing to one org, a@hanzo.ai
// to another — and each of those is signed into several applications from
// several devices. The CLI has modelled this since multi-identity landed there
// (`hanzo auth list` prints "* hanzo/z", `use` switches, owner is the billing
// org); the browser never did. These four endpoints give the browser the same
// model with the same vocabulary — identity, active, owner — so a person reads
// one thing in the terminal and on the account page.
//
// Every one of them is SELF-SCOPED: the answer is derived from the signed cookie
// the caller presented, never from a parameter naming whose account to read or
// end. There is no identity you can ask about that you are not already signed in
// as, so no caller can enumerate or sign out anybody else.
const (
	PathHub         = "/v1/iam/account/hub"      // GET  — every identity, session and last-used app
	PathHubUse      = "/v1/iam/account/use"      // POST — make a held identity active
	PathHubSignOut  = "/v1/iam/account/sign-out" // POST — end this session, this identity, or everything
	PathHubIdentity = "identity"                 // the sign-out scopes
	scopeSession    = "session"
	scopeEverywhere = "everywhere"
)

// routeHub registers the account-hub surface on the PUBLIC group, alongside the
// other cookie-authenticated front-door reads (frontdoor.go). Each handler
// resolves the caller from the cookie itself and refuses anonymously.
func routeHub(r zip.Router, db orm.DB) {
	r.Get(PathHub, hubHandler(db))
	r.Post(PathHubUse, hubUseHandler(db))
	r.Post(PathHubSignOut, hubSignOutHandler(db))
}

// hubIdentity is one identity the browser holds, with everywhere it is signed in.
type hubIdentity struct {
	Owner       string `json:"owner"` // the IAM org — what gets billed
	Name        string `json:"name"`
	Identity    string `json:"identity"` // "owner/name", as the CLI prints it
	Active      bool   `json:"active"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	Avatar      string `json:"avatar,omitempty"`
	Sub         string `json:"sub,omitempty"`

	Sessions []hubSession `json:"sessions"`
	LastUsed *hubSession  `json:"lastUsed,omitempty"`
}

// hubSession is one application this identity is signed into, from one device.
type hubSession struct {
	Application string `json:"application"`
	DisplayName string `json:"displayName,omitempty"`
	Url         string `json:"url,omitempty"`
	Device      string `json:"device,omitempty"`
	Started     string `json:"started,omitempty"`
	LastSeen    string `json:"lastSeen,omitempty"`
	Current     bool   `json:"current"` // the cookie THIS request rode in on
}

// hubHandler answers, for the human at this browser: every identity they are
// signed in as, which one is active and which org it bills to, every live
// session with its device and when it was last used, and the app each identity
// most recently used so the page can offer a jump straight back into it.
//
// The identity list comes from the signed cookie and the session list from the
// session store — the same store a sign-out ends — so what is listed is exactly
// what would still authenticate. Anonymous callers get {status:"error"}, the
// same fail-closed envelope get-account uses.
func hubHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		held, ok := sessions.Held(ctx, c.Fiber(), db)
		if !ok {
			return c.JSON(200, accountResponse{Status: "error", Msg: "please sign in first"})
		}
		active, _ := held.Current()
		out := make([]hubIdentity, 0, len(held.Ids))
		for n, id := range held.Ids {
			out = append(out, describeIdentity(ctx, db, id, n == held.Active, active))
		}
		return c.JSON(200, accountResponse{
			Status: "ok",
			Sub:    active.String(),
			Name:   active.Name,
			Data:   out,
		})
	}
}

// describeIdentity assembles one identity's row: who they are, and every session
// they hold across every application.
func describeIdentity(ctx context.Context, db orm.DB, id sessions.Id, isActive bool, current sessions.Id) hubIdentity {
	h := hubIdentity{
		Owner:    id.Owner,
		Name:     id.Name,
		Identity: id.String(),
		Active:   isActive,
	}
	if u, err := store.GetUserByName(ctx, db, id.Owner, id.Name); err == nil && u != nil {
		h.DisplayName, h.Email, h.Avatar, h.Sub = u.DisplayName, u.Email, u.Avatar, subjectOf(u)
	}
	rows, err := orm.TypedQuery[schema.Session](db).
		Filter("Owner=", id.Owner).Filter("Name=", id.Name).GetAll(ctx)
	if err != nil {
		return h
	}
	sessions.Enrich(ctx, db, rows)
	h.Sessions = flatten(rows, id, current, isActive)
	// Last used is DERIVED from session activity, not recorded separately: the
	// session that was most recently presented IS the app you were last in, and a
	// parallel "last app" column could disagree with which sessions are live.
	sort.SliceStable(h.Sessions, func(a, b int) bool { return h.Sessions[a].LastSeen > h.Sessions[b].LastSeen })
	if len(h.Sessions) > 0 && h.Sessions[0].LastSeen != "" {
		last := h.Sessions[0]
		h.LastUsed = &last
	}
	return h
}

// flatten turns session rows into one entry per live browser cookie. A row with
// no observation yet (issued before the session store recorded devices) still
// yields one entry per live cookie, so a session is never invisible just because
// we know nothing about the device carrying it.
func flatten(rows []*schema.Session, id, current sessions.Id, isActive bool) []hubSession {
	out := []hubSession{}
	for _, s := range rows {
		if s == nil {
			continue
		}
		seen := map[string]schema.Sid{}
		for _, v := range s.Seen {
			seen[v.Id] = v
		}
		for _, sid := range s.SessionId {
			v := seen[sid]
			started := v.Created
			if started == "" {
				started = s.CreatedTime
			}
			out = append(out, hubSession{
				Application: s.Application,
				DisplayName: s.ApplicationDisplayName,
				Url:         s.HomepageUrl,
				Device:      v.Device,
				Started:     started,
				LastSeen:    v.LastSeen,
				// "Current" means THIS request's cookie: the active identity's own sid.
				// Marking it is what stops someone ending the session they are reading
				// the page in without meaning to.
				Current: isActive && sid == current.SID && s.Application == current.Application,
			})
		}
	}
	return out
}

// hubUseIn names which held identity to make active.
type hubUseIn struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// hubUseHandler switches which of the identities this browser holds is the
// active one — the browser's `hanzo auth use`.
//
// It grants nothing: the target must already be in the verified cookie with a
// live session, so this only chooses among credentials the browser already
// proved it holds. An identity that is not held is refused rather than ignored,
// because a switch that silently left you as someone else is how you act as the
// wrong principal.
func hubUseHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var in hubUseIn
		if err := c.Bind(&in); err != nil {
			return c.JSON(200, accountResponse{Status: "error", Msg: "owner and name are required"})
		}
		owner, name := strings.TrimSpace(in.Owner), strings.TrimSpace(in.Name)
		if owner == "" || name == "" {
			return c.JSON(200, accountResponse{Status: "error", Msg: "owner and name are required"})
		}
		if !sessions.Use(c.Context(), c.Fiber(), db, owner, name) {
			return c.JSON(200, accountResponse{Status: "error", Msg: "you are not signed in as " + owner + "/" + name})
		}
		return c.JSON(200, accountResponse{Status: "ok", Sub: owner + "/" + name, Name: name})
	}
}

// hubSignOutIn selects what to end. Scope defaults to the narrowest thing that
// makes sense — the identity you name, or the active one when you name none.
type hubSignOutIn struct {
	Scope string `json:"scope"` // "session" | "identity" | "everywhere"
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// hubSignOutOut reports what was actually ended, so the page can say so rather
// than assume.
type hubSignOutOut struct {
	Scope      string   `json:"scope"`
	Identities []string `json:"identities"`
}

// hubSignOutHandler ends a sign-in at one of three widths:
//
//	session     — this browser only: the cookie goes, tokens survive elsewhere.
//	identity    — one identity everywhere: its cookie entry AND every token row it
//	              holds in every application. Other identities stay signed in.
//	everywhere  — every identity this browser holds, and every token each of them
//	              holds. Nothing mintable is left behind.
//
// "Everywhere" is the one that has to be true rather than reassuring. It revokes
// the sid server-side (a captured copy of the cookie stops resolving), expires
// the cookie, and deletes every token row — with its whole refresh-rotation
// family, because a refresh chain rotates into NEW rows and deleting only the
// rows found by (user, app) leaves a rotated descendant alive and mintable. A
// downstream application's next call 401s: not because a JWT expired, which
// takes days, but because the token row it would refresh against is gone.
func hubSignOutHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		var in hubSignOutIn
		_ = c.Bind(&in) // an empty body means "the active identity"

		switch in.Scope {
		case scopeEverywhere:
			ids, ok := sessions.Clear(ctx, c.Fiber(), db)
			if !ok {
				return c.JSON(200, accountResponse{Status: "error", Msg: "not signed in"})
			}
			out := hubSignOutOut{Scope: scopeEverywhere}
			for _, id := range ids {
				revokeEverything(ctx, db, id.Owner+"/"+id.Name)
				out.Identities = append(out.Identities, id.String())
			}
			return c.JSON(200, accountResponse{Status: "ok", Data: out})

		case scopeSession:
			// End only this browser. The cookie is the session, so clearing it IS
			// the sign-out; tokens the identity holds elsewhere are untouched, which
			// is the whole difference from "identity".
			ids, ok := sessions.Clear(ctx, c.Fiber(), db)
			if !ok {
				return c.JSON(200, accountResponse{Status: "error", Msg: "not signed in"})
			}
			out := hubSignOutOut{Scope: scopeSession}
			for _, id := range ids {
				out.Identities = append(out.Identities, id.String())
			}
			return c.JSON(200, accountResponse{Status: "ok", Data: out})

		default:
			// One identity. Named, or the active one — never a guess at which of
			// several the caller meant.
			owner, name := strings.TrimSpace(in.Owner), strings.TrimSpace(in.Name)
			if owner == "" || name == "" {
				held, ok := sessions.Held(ctx, c.Fiber(), db)
				if !ok {
					return c.JSON(200, accountResponse{Status: "error", Msg: "not signed in"})
				}
				id, ok := held.Current()
				if !ok {
					return c.JSON(200, accountResponse{Status: "error", Msg: "no active identity — name one to sign out"})
				}
				owner, name = id.Owner, id.Name
			}
			gone, ok := sessions.Drop(ctx, c.Fiber(), db, owner, name)
			if !ok {
				return c.JSON(200, accountResponse{Status: "error", Msg: "you are not signed in as " + owner + "/" + name})
			}
			revokeEverything(ctx, db, gone.Owner+"/"+gone.Name)
			return c.JSON(200, accountResponse{
				Status: "ok",
				Data:   hubSignOutOut{Scope: PathHubIdentity, Identities: []string{gone.String()}},
			})
		}
	}
}

// revokeEverything retires every token row a user holds in EVERY application —
// the revoke-everything variant of revokeGrant, which is scoped to one
// application. Each row's whole refresh-rotation family goes with it, for the
// same reason revokeGrant sweeps families: a rotated descendant left alive is
// still mintable, so deleting only the rows a query returns is a gesture, not a
// revocation.
//
// Best-effort by construction — a sign-out must not fail because a row was
// already gone, and revocation is idempotent (store.DeleteToken treats a missing
// row as success).
func revokeEverything(ctx context.Context, db orm.DB, user string) {
	if user == "" || user == "/" {
		return // never a query that would match every row
	}
	rows, err := store.ListTokensByUser(ctx, db, user)
	if err != nil {
		return
	}
	for _, row := range rows {
		if row.RefreshFamily != "" {
			if family, err := store.ListTokensByRefreshFamily(ctx, db, row.RefreshFamily); err == nil {
				for _, t := range family {
					_ = store.DeleteToken(ctx, db, t)
				}
			}
		}
		_ = store.DeleteToken(ctx, db, row)
	}
}

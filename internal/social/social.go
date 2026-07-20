// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package social finishes a federated sign-in: it lands the browser coming back
// from Google/GitHub/GitLab, decides which account that third-party identity may
// act as, and hands the result to the OIDC code seam (HIP-0111 §7).
//
// The decision is the whole package, and it is stated once, in link.go: an
// account is selected by a provider subject already on file or by an email both
// sides assert is verified — never by a username, never by a phone. v1 links by
// username unconditionally (controllers/auth.go:1084-1090), which is a live
// account takeover: an attacker whose GitHub login equals a victim's Hanzo
// username signs in as the victim.
//
// The upstream half of the hop is internal/idp; the protocol half — parking the
// authorize request and minting the code — is internal/oidc.
package social

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/idp"
	"github.com/hanzoai/iam2/internal/oidc"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
	"github.com/hanzoai/iam2/internal/users"
)

// Mount registers the social surface: the callback the providers redirect back
// to, and the unlink endpoint that removes a link.
func Mount(app *zip.App, db orm.DB) {
	app.Get(idp.PathCallback, callback(db))
	MountUnlink(app, db)
}

// callback lands the browser returning from a provider and turns the upstream
// code into an IAM authorization code on the application's registered
// redirect_uri.
//
// It is reachable without a bearer — a browser coming back from Google holds
// nothing — so it trusts exactly one thing from the request: the state handle,
// which only names a request THIS server parked. Everything else (the
// application, the tenant, the provider, the PKCE challenge the result binds
// to) is read from that parked row, never from the query.
func callback(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		// 1. Claim the parked request. One shot: a replayed state is refused
		// here, before it can drive a second exchange.
		state, err := oidc.Claim(ctx, db, c.Query("state"))
		if err != nil {
			return fail(c, "the sign-in request expired or was already used")
		}
		if c.Query("code") == "" {
			// The provider refused or the user declined. Report it on the
			// application's own redirect, which the authorize step validated.
			return back(c, state, url.Values{"error": {or(c.Query("error"), "access_denied")}})
		}

		// 2. Resolve the application from the parked row — its own (owner, name),
		// so a row can only ever name an application under the owner that parked
		// it. The provider is always the shared, admin-owned record: one Google
		// client for the whole platform, never a per-tenant one (HIP-0111 §7).
		app, err := store.GetApplicationByName(ctx, db, state.Owner, state.Application)
		if err != nil || app == nil {
			return fail(c, "the application does not exist")
		}
		item := providerItem(app, state.Provider)
		if item == nil {
			return fail(c, "the application has no provider "+state.Provider)
		}
		provider, err := store.GetProvider(ctx, db, providerOwner(item), state.Provider)
		if err != nil || provider == nil {
			return fail(c, "the provider does not exist")
		}

		// 3. Trade the upstream code for the identity. The redirect URI is
		// derived from this server's origin inside idp.Open, so it is the same
		// bytes the authorize hop sent — the exchange fails otherwise.
		conn, err := idp.Open(provider, oidc.Origin(c))
		if err != nil {
			return fail(c, "the provider is not supported")
		}
		tok, err := conn.Exchange(ctx, c.Query("code"), state.Verifier)
		if err != nil {
			return fail(c, "the provider rejected the sign-in")
		}
		id, err := conn.Identify(ctx, tok)
		if err != nil {
			return fail(c, err.Error())
		}

		// 4. The provider's email-domain restriction, when the operator set one.
		// v1 reports this failure and then carries on into sign-up anyway (a
		// missing return, auth.go:1016-1025); refusing means refusing.
		if !allowed(provider.EmailRegex, id.Email) {
			return fail(c, "the email is not allowed by the provider")
		}

		// 5. The tenant is the application's organization, from the resolved
		// application — never a request parameter (HIP-0111 Invariant 3).
		org := app.Organization
		u, err := resolve(ctx, db, org, provider.Type, app, id)
		if err != nil {
			return fail(c, err.Error())
		}
		if u == nil {
			u, err = signup(ctx, db, org, app, item, provider.Type, id)
		} else {
			err = attach(ctx, db, u, provider.Type, id)
		}
		if err != nil {
			return fail(c, err.Error())
		}

		// 6. Mint through the ONE code seam, bound to the challenge the
		// application sent at authorize — so only the client instance that
		// started the flow can redeem what lands.
		code, err := oidc.Issue(ctx, db, app, u, oidc.Params{
			Scope:     state.Scope,
			Redirect:  state.RedirectUri,
			Nonce:     state.Nonce,
			Challenge: state.CodeChallenge,
			Method:    state.CodeChallengeMethod,
			Resource:  state.Resource,
		})
		if err != nil {
			return fail(c, err.Error())
		}
		return back(c, state, url.Values{"code": {code.Code}})
	}
}

// signup creates the account a new third-party identity signs in as.
func signup(ctx context.Context, db orm.DB, org string, app *schema.Application, item *schema.ProviderItem, kind string, id *idp.Identity) (*schema.User, error) {
	// Sign-up MINTS a principal, so it may never mint one into a reserved
	// platform organization. An application names the organization it signs
	// users into, and any org admin may register an application; a brand-new
	// account in the reserved "admin" org IS a SuperAdmin (internal/authz), so
	// without this an org admin could register an app naming that organization
	// and self-provision platform sudo with one GitHub sign-in. The reserved set
	// is the same trust boundary the signing-cert gate uses — one list, one
	// predicate (HIP-0111 Invariant 4).
	if store.IsSigningCertOwner(org) {
		return nil, zip.ErrForbidden("sign-up into a reserved organization is not permitted")
	}
	if !app.EnableSignUp {
		return nil, zip.ErrForbidden("the account for provider " + kind + " and username " +
			id.Username + " does not exist and is not allowed to sign up as a new account")
	}
	if !item.CanSignUp {
		return nil, zip.ErrForbidden("the account for provider " + kind + " and username " +
			id.Username + " does not exist and is not allowed to sign up as a new account via " + kind)
	}

	l, ok := links[kind]
	if !ok {
		return nil, idp.ErrKind
	}
	name, err := username(ctx, db, org, id)
	if err != nil {
		return nil, err
	}
	u := schema.User{
		Owner:             org,
		Name:              name,
		Type:              "normal-user",
		DisplayName:       display(id),
		Avatar:            id.Avatar,
		Email:             id.Email,
		Phone:             id.Phone,
		SignupApplication: app.Name,
		RegisterType:      "Application Signup",
		RegisterSource:    org + "/" + app.Name,
		// The account inherits the provider's verdict on the address, not a
		// blanket true: an unverified address stays unverified, so a later
		// sign-in cannot link to this row by email either.
		EmailVerified: id.Verified,
		Groups:        groups(app, item),
	}
	// The link lands with the row itself, so an account never exists in a state
	// where its identity is unrecorded and a retry would mint a second one.
	l.write(&u, id.Subject)
	// Create through the user API, the one place an account is minted — so the
	// credential invariant holds here too. No password is set: a social account
	// has no digest, and users.VerifyPassword refuses an empty one, so this row
	// cannot be signed into with a password until its owner sets one.
	return users.New(db).Create(ctx, &users.CreateInput{User: u})
}

// username picks the new account's name: the identity's handle, or its email
// when the organization signs users in by address. A name already taken in the
// organization is suffixed with a random segment rather than colliding — an
// existing account is NEVER selected by a name match (see link.go).
func username(ctx context.Context, db orm.DB, org string, id *idp.Identity) (string, error) {
	name := id.Username
	o, err := store.GetOrganization(ctx, db, org)
	if err != nil {
		return "", err
	}
	if o != nil && o.UseEmailAsUsername && id.Email != "" {
		name = id.Email
	}
	if name == "" {
		name = id.Subject
	}
	taken, err := store.GetUserByName(ctx, db, org, name)
	if err != nil {
		return "", err
	}
	if taken == nil {
		return name, nil
	}
	suffix, err := segment()
	if err != nil {
		return "", err
	}
	return name + "_" + suffix, nil
}

// groups is the new account's group, by precedence: the provider link's sign-up
// group, else the application's default group.
//
// v1 also honors an invitation's sign-up group; iam2 has no invitation on this
// path — the hop carries no invitation code — so there is nothing to honor.
func groups(app *schema.Application, item *schema.ProviderItem) []string {
	if item.SignupGroup != "" {
		return []string{item.SignupGroup}
	}
	if app.DefaultGroup != "" {
		return []string{app.DefaultGroup}
	}
	return nil
}

// providerItem finds the application's link to a provider by name. The parked
// row named it, so this re-reads the link the hop was started from.
func providerItem(app *schema.Application, name string) *schema.ProviderItem {
	for _, it := range app.Providers {
		if it != nil && it.Name == name {
			return it
		}
	}
	return nil
}

// providerOwner is the organization a provider record is read from: always the
// reserved admin org unless the link pins one. Providers are shared platform
// records — one GitHub OAuth client for every tenant (HIP-0111 §7) — which is
// the same default store.EnrichProviders applies.
func providerOwner(item *schema.ProviderItem) string {
	if item.Owner != "" {
		return item.Owner
	}
	return "admin"
}

// allowed reports whether an address satisfies the provider's email
// restriction. An unset restriction allows everything; an unparseable one
// allows nothing, because a broken rule must not silently become no rule.
func allowed(rule, email string) bool {
	if rule == "" {
		return true
	}
	re, err := regexp.Compile(rule)
	if err != nil {
		return false
	}
	return re.MatchString(email)
}

// back returns the browser to the application's own redirect_uri — the one the
// authorize step validated against the registered set — echoing the
// application's original state so its client matches the response to its
// request.
func back(c *zip.Ctx, state *schema.Token, v url.Values) error {
	if state.State != "" {
		v.Set("state", state.State)
	}
	sep := "?"
	if strings.Contains(state.RedirectUri, "?") {
		sep = "&"
	}
	return c.Redirect(302, state.RedirectUri+sep+v.Encode())
}

// fail answers in place. The browser is mid-hop and the request is already
// consumed, so there is nothing to redirect to that is worth trusting; the
// message is server-controlled.
func fail(c *zip.Ctx, msg string) error {
	c.SetHeader("Content-Type", "text/plain; charset=utf-8")
	return c.String(400, "sign-in error: "+msg)
}

// segment returns a short random suffix that makes a taken name unique.
func segment() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

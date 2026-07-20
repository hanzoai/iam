// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package serviceaccounts serves the agent/bot identity surface at
// /v1/iam/service-accounts — create an identity and mint its first key, list an
// org's identities, rotate a key, revoke an identity.
//
// A service account IS a user row (schema.User, Type "service-account"), not a
// new entity: it reuses the whole identity surface — the store, the redaction
// contract, the org-scoped claims a token carries — so an agent is a principal
// like any other. What makes it a service account rather than a human:
//
//   - Type is serviceAccount, and its Name is the canonical <org>-<agent>
//     handle, so it maps 1:1 to a chat/team bot member and is unambiguous.
//   - It has NO password and can never sign in interactively. Its only
//     credential is an API key whose secret is stored ONLY as an argon2id digest
//     (internal/cred) — the raw secret is returned exactly once, at mint, and is
//     unrecoverable after.
//
// Authorization is v1's, verbatim (controllers/service_account.go): minting a
// key is the same trust boundary as minting a user's key, so create/rotate/
// delete need the mint capability (an app) or org-admin authority over the
// target org (a human). Listing — names and metadata only — takes the read-only
// capability instead, and that grant is additionally tenant-bound: app/hanzo-team
// may list organization=hanzo and no other tenant's. A read capability can never
// mint, rotate, or delete.
package serviceaccounts

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/cred"
	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/keys"
	"github.com/hanzoai/iam2/internal/schema"
)

// Paths — the verb face the live consumers call (team's bot member sync reads
// the list; the console provisions).
const (
	Path     = "/v1/iam/service-accounts"
	PathKeys = Path + "/:name/keys"
	PathOne  = Path + "/:name"
)

// serviceAccount is the User.Type discriminator. Readers ask `is()`, never the
// literal, so the value lives in exactly one place.
const serviceAccount = "service-account"

// unauthorized is v1's refusal message, verbatim.
const unauthorized = "auth:Unauthorized operation"

// Mount registers the service-account surface on app, backed by db.
func Mount(app *zip.App, db orm.DB) {
	app.Get(Path, list(db))
	app.Post(Path, create(db))
	app.Post(PathKeys, rotate(db))
	app.Delete(PathOne, revoke(db))
}

// request is the create body: the owning org, the agent handle (bare or already
// canonical), and an optional back-reference to the agent record this identity
// embodies.
type request struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	AgentRef     string `json:"agentRef"`
}

// minted is the ONE shape a freshly minted credential leaves in — the only
// response that ever carries a raw secret, and only at the moment it is created.
type minted struct {
	Owner        string `json:"owner"`
	Name         string `json:"name,omitempty"`
	Type         string `json:"type,omitempty"`
	AgentRef     string `json:"agentRef,omitempty"`
	AccessKey    string `json:"accessKey"`
	AccessSecret string `json:"accessSecret"`
}

// create serves POST /v1/iam/service-accounts: provision the identity and mint
// its first key, returning the raw secret exactly once.
func create(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var in request
		if err := c.Bind(&in); err != nil {
			return httpx.Err(c, err.Error())
		}
		if in.Organization == "" {
			return httpx.Err(c, "organization is required")
		}
		p, ok := authz.From(c.Context())
		if !ok || !admin(p, in.Organization) {
			return httpx.Err(c, unauthorized)
		}
		name := canonical(in.Organization, in.Name)
		if name == "" {
			return httpx.Err(c, "a valid name is required")
		}

		ctx := c.Context()
		if u, err := find(ctx, db, in.Organization, name); err != nil {
			return httpx.Err(c, err.Error())
		} else if u != nil {
			// Refuse a collision with ANY principal, human or bot, so a service
			// account can never hijack or be hijacked by a username.
			return httpx.Err(c, "a user named "+name+" already exists in organization "+in.Organization)
		}

		sa := orm.New[schema.User](db)
		sa.Owner, sa.Name = in.Organization, name
		sa.Type, sa.DisplayName, sa.Tag = serviceAccount, name, in.AgentRef
		sa.SetId(in.Organization + "/" + name)
		key, secret, err := mint(sa)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if err := sa.CreateCtx(ctx); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, &minted{
			Owner: sa.Owner, Name: sa.Name, Type: sa.Type, AgentRef: sa.Tag,
			AccessKey: key, AccessSecret: secret,
		})
	}
}

// list serves GET /v1/iam/service-accounts?organization=<org>: names and
// metadata, never secrets. Paginated in memory over the already org-scoped
// slice — the set per org is small, so a dedicated count query is overkill
// (v1 service_account.go:296-307).
func list(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		org := c.Query("organization")
		if org == "" {
			return httpx.Err(c, "organization is required")
		}
		p, ok := authz.From(c.Context())
		if !ok || !read(p, org) {
			return httpx.Err(c, unauthorized)
		}
		all, err := orm.TypedQuery[schema.User](db).
			Filter("Owner=", org).Filter("Type=", serviceAccount).Order("Name").GetAll(c.Context())
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		for _, sa := range all {
			redact(sa)
		}
		page := paginate(all, atoi(c.Query("p")), atoi(c.Query("pageSize")))
		return c.JSON(200, httpx.Response{Status: "ok", Data: page, Data2: len(all)})
	}
}

// rotate serves POST /v1/iam/service-accounts/:name/keys: mint a fresh key,
// invalidating the prior one, and return the new raw secret exactly once.
func rotate(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		sa, err := load(c, db)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		key, secret, err := mint(sa)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if err := sa.UpdateCtx(c.Context()); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, &minted{Owner: sa.Owner, Name: sa.Name, AccessKey: key, AccessSecret: secret})
	}
}

// revoke serves DELETE /v1/iam/service-accounts/:name.
func revoke(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		sa, err := load(c, db)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if err := sa.DeleteCtx(c.Context()); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, true)
	}
}

// load resolves the :name service account within the ?organization= org and
// authorizes the caller for MUTATION — the shared preamble of rotate and delete,
// so neither can reach a row the admin gate did not clear.
func load(c *zip.Ctx, db orm.DB) (*schema.User, error) {
	org, name := c.Query("organization"), c.Param("name")
	if org == "" || name == "" {
		return nil, zip.ErrBadRequest("organization and name are required")
	}
	p, ok := authz.From(c.Context())
	if !ok || !admin(p, org) {
		return nil, zip.ErrForbidden(unauthorized)
	}
	sa, err := find(c.Context(), db, org, name)
	if err != nil {
		return nil, err
	}
	if sa == nil || !is(sa) {
		return nil, zip.ErrNotFound("the service account " + name + " does not exist in organization " + org)
	}
	return sa, nil
}

// admin is the gate for every credential MUTATION — create, rotate, revoke
// (v1 authorizeServiceAccountAdmin + serviceAccountHumanAdminAllowed). A
// confidential client must hold the mint capability; a human must be a
// SuperAdmin or an admin of the target org itself, so a tenant admin can never
// provision an identity in another tenant.
func admin(p *authz.Principal, org string) bool {
	if p == nil || org == "" {
		return false
	}
	if p.App != "" {
		return authz.Allowed(p, authz.CapKeyMint)
	}
	return p.Super || (p.Admin && p.Org == org)
}

// read is the gate for the LIST surface, which returns names and metadata only
// (v1 authorizeServiceAccountRead). It is deliberately weaker than admin for
// apps and IDENTICAL for humans:
//
//   - the mint capability is a superset of read: an orchestrator that already
//     provisions in any org may enumerate any org;
//   - otherwise the read-only capability suffices, but ONLY within the org the
//     app's own <org>-<app> name binds it to. Both conditions are required, so a
//     leaked reader credential can enumerate one tenant's bot names and nothing
//     else — and can never mint, rotate, or delete, which stay on admin.
func read(p *authz.Principal, org string) bool {
	if p == nil || org == "" {
		return false
	}
	if p.App != "" {
		return authz.Allowed(p, authz.CapKeyMint) ||
			(authz.Allowed(p, authz.CapServiceAccountRead) && authz.BoundToOrg(p, org))
	}
	return p.Super || (p.Admin && p.Org == org)
}

// mint (re)generates the identity's credential: a fresh access key (the
// plaintext lookup handle) and a fresh secret whose argon2id DIGEST — never the
// secret — is stored. Any prior key stops authenticating the moment this
// persists. The raw secret is returned to the caller and never written.
func mint(sa *schema.User) (key, secret string, err error) {
	key, secret = keys.Mint("hk", ""), keys.Mint("hk", "")
	hash, err := cred.Hash(secret)
	if err != nil {
		return "", "", zip.ErrInternal("hash service account secret: " + err.Error())
	}
	// The access key is a public lookup handle, not a secret, so it is stored
	// verbatim; only its secret sibling is digested.
	sa.AccessKey = key
	sa.AccessSecretHash = hash
	sa.AccessSecret = "" // never persist the plaintext, and clear any legacy one
	return key, secret, nil
}

// canonical maps a (org, agent) request pair to the <org>-<agent> handle: a bare
// agent segment is prefixed, an already-canonical name is kept. Returns "" when
// the result is not a well-formed handle, so a malformed name is refused at the
// boundary rather than persisted.
func canonical(org, name string) string {
	if name == "" {
		return ""
	}
	if !boundTo(org, name) {
		name = org + "-" + name
	}
	if !valid(name) {
		return ""
	}
	return name
}

// boundTo reports whether name already carries the "<org>-" prefix with a
// non-empty agent segment.
func boundTo(org, name string) bool {
	prefix := org + "-"
	return len(name) > len(prefix) && strings.HasPrefix(name, prefix)
}

// valid reports whether name is a well-formed handle: alphanumerics with single
// -/_/. separators between segments, never leading, trailing, or doubled. A
// handle is an identity, so anything else is refused rather than normalized.
func valid(name string) bool {
	if name == "" || sep(rune(name[0])) || sep(rune(name[len(name)-1])) {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case sep(r):
			if i > 0 && sep(rune(name[i-1])) {
				return false // doubled separator
			}
		default:
			return false
		}
	}
	return true
}

func sep(r rune) bool { return r == '-' || r == '_' || r == '.' }

// is reports whether u is a service-account principal.
func is(u *schema.User) bool { return u != nil && u.Type == serviceAccount }

// find resolves one user by (owner, name); (nil, nil) when absent.
func find(ctx context.Context, db orm.DB, owner, name string) (*schema.User, error) {
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Name=", name).First()
	if err != nil {
		if err == orm.ErrNotFound {
			return nil, nil
		}
		return nil, zip.ErrInternal(err.Error())
	}
	return u, nil
}

// redact strips every credential field before an identity is listed. The secret
// exists only as a digest, and even that never leaves: a list is names and
// metadata (v1 masks the same three columns).
func redact(sa *schema.User) {
	sa.AccessKey = ""
	sa.AccessSecret = ""
	sa.AccessSecretHash = ""
	sa.PasswordHash = ""
	sa.PasswordSalt = ""
}

// paginate returns the 1-indexed page of size n, clamped to the slice. Absent
// paging (either value unset) returns everything, matching v1.
func paginate(all []*schema.User, page, size int) []*schema.User {
	if page <= 0 || size <= 0 {
		return all
	}
	start := (page - 1) * size
	if start > len(all) {
		start = len(all)
	}
	end := start + size
	if end > len(all) {
		end = len(all)
	}
	return all[start:end]
}

// atoi parses a non-negative paging parameter; anything else is 0 ("unset").
func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

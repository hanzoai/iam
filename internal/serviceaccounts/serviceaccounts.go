// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/keys"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
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

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the service-account surface on app, backed by db.
//
// The LIST is a typed op — so it is in the OpenAPI document, the SDKs, the CLI
// and the MCP tool list, which a raw handler is in none of. The three credential
// writes stay raw, deliberately: a typed op also passes through the op-invoke
// authorizer (authz.Authorize), and routing a write through it would authorize
// the decoded (Owner, Name) — which these bodies do not carry — instead of the
// admin() gate each already applies. That is a change to WHO may mint, so it is
// a decision, not a projection.
//
// The read reaches that authorizer and is admitted, by construction: it admits a
// GET whose decoded input names no owner, and `query` declares no Owner field and
// no AuthzTarget() for it to read. The tenant gate is unmoved — read() on the
// ?organization= the handler itself binds, exactly as before.
//
// A refusal is a VALUE here (httpx.Bad), never a returned error: an error renders
// zip's {"status":<int>,"error":…} instead of this surface's envelope.
func Route(app *zip.App, db orm.DB) {
	zip.Get[query, httpx.Answer](app, Path, list(db),
		zip.WithStatus(200, 400),
		zip.WithTags("service-accounts"))
	app.Post(Path, create(db))
	app.Post(PathKeys, rotate(db))
	app.Delete(PathOne, revoke(db))
}

// query is the list request: the organization to enumerate, and optionally which
// page of it.
type query struct {
	// Organization is the organization whose service accounts to list. Required.
	Organization string `json:"organization"`
	// P is the 1-indexed page to return. Paging takes both p and pageSize —
	// leave either out, or send something that is not a number, and the whole
	// list comes back.
	P int `json:"p"`
	// Size is how many accounts a page holds.
	Size int `json:"pageSize"`
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

// create makes a service account — an identity for a program rather than a
// person, for a script, a bot or a deployment that has to authenticate on its
// own.
//
// It comes back with its first key, and the secret half is shown ONCE, here.
// There is no way to read it again; if you lose it, rotate.
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
		// Subject is the (owner,name) natural key, NOT a minted UUID — a service account
		// is a machine identity whose sub is its stable owner/name (the M2M principal),
		// so this bypasses the canonical users.Create path and diverges from the "sub is
		// always a UUID" invariant (F-A1). It is NOT an impersonation vector: owner is the
		// caller's authorized org and name is canonicalized server-side with no client Id,
		// and store.GetUserById fails closed on an empty/duplicate Id. Minting a UUID here
		// would change the M2M subject shape, so it is deferred to a deliberate migration
		// rather than folded into this security rework.
		sa.SetId(in.Organization + "/" + name)
		key, secret, err := mint(ctx, db, sa)
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

// list returns your organization's service accounts — what each is called and
// when it was created. Never their secrets: a key's secret half exists in a
// response exactly once, when it is minted. Paginated in memory over the already org-scoped
// slice — the set per org is small, so a dedicated count query is overkill
// (v1 service_account.go:296-307).
func list(db orm.DB) zip.TypedHandler[query, httpx.Answer] {
	return func(ctx context.Context, in *query) (*httpx.Answer, error) {
		if in.Organization == "" {
			return httpx.Bad(400, "organization is required", ""), nil
		}
		p, ok := authz.From(ctx)
		if !ok || !read(p, in.Organization) {
			return httpx.Bad(400, unauthorized, ""), nil
		}
		all, err := orm.TypedQuery[schema.User](db).
			Filter("Owner=", in.Organization).Filter("Type=", serviceAccount).Order("Name").GetAll(ctx)
		if err != nil {
			return httpx.Bad(400, err.Error(), ""), nil
		}
		for _, sa := range all {
			redact(sa)
		}
		// data2 is the TOTAL, not the page length — v1's contract, so a caller
		// paging through knows how far it has to go.
		return httpx.Good(paginate(all, in.P, in.Size), len(all)), nil
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
		key, secret, err := mint(c.Context(), db, sa)
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

// load resolves the :name service account within its organization and authorizes
// the caller for MUTATION — the shared preamble of rotate and delete, so neither
// can reach a row the admin gate did not clear.
//
// The organization arrives as ?organization=, or in the body under the same
// name. Both spellings carry the same value, and the body is read only when the
// query is absent, so nothing that works today changes.
//
// The body form is what makes these two callable at all from a generated
// client. Every one of them is built from this service's own OpenAPI, and a
// query parameter reaches that document only from a TYPED handler's input
// struct — `list` declares one and gets `--organization`; rotate and revoke read
// the query straight off the context, so the document says their only parameter
// is the path, the generated flag never exists, and the call comes back
// "organization and name are required" with no way to supply it. `create`
// already takes the org in its body and has always worked for that reason.
func load(c *zip.Ctx, db orm.DB) (*schema.User, error) {
	org, name := c.Query("organization"), c.Param("name")
	if org == "" {
		org = orgFromBody(c.Body())
	}
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

// orgFromBody reads the organization out of a JSON request body, and answers ""
// for anything it cannot — no body, not an object, no such field. A malformed
// body is not an error here: the caller is then simply one that supplied no
// organization, which load already has an answer for.
func orgFromBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var in struct {
		Organization string `json:"organization"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return ""
	}
	return in.Organization
}

// admin is the gate for every credential MUTATION — create, rotate, revoke
// (v1 authorizeServiceAccountAdmin + serviceAccountHumanAdminAllowed). A
// confidential client must hold the mint capability; a human must be a
// SuperAdmin or an admin of the target org itself, so a tenant admin can never
// provision an identity in another tenant.
//
// A RESERVED SYSTEM ORG IS NOT A TENANT, and the mint capability does not reach
// one. store.IsReservedOrg is the same predicate signup, onboarding, federated
// provisioning and membership grants already consult, composed the same way
// memberships.mayGrant composes it — reserved unless the caller is a SuperAdmin —
// so the set of orgs a customer-driven flow may never land a principal in is
// stated once and this surface stops being the exception.
//
// It was the exception, and the escalation was total: create takes the target org
// from the request body verbatim, and a row's HOME org is its platform authority
// (authz builds Principal.Super from memberOf(adminOrg), and memberOf answers
// home-or-membership). So `{"organization":"admin"}` minted a live principal in
// the reserved org, holding pk-/sk- keys, that authenticates as a SuperAdmin —
// turning "may provision identities" into platform sudo, cross-tenant, in one
// call. The app principal itself is never Admin and never Super by construction;
// nothing stopped it CREATING one that is.
//
// The capability is unbound by org for a reason (an orchestrator provisions for
// every tenant), so the binding that matters is not which tenant but whether the
// target is a tenant at all. A human SuperAdmin keeps the ability, because that
// is already the authority the reserved org denotes.
func admin(p *authz.Principal, org string) bool {
	if p == nil || org == "" {
		return false
	}
	if store.IsReservedOrg(org) && !p.Super {
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

// mint (re)generates the identity's credential: a fresh pk- access key (the
// plaintext lookup handle) and a fresh sk- secret whose argon2id DIGEST — never the
// secret — is stored. Any prior key stops authenticating the moment this
// persists. The raw secret is returned to the caller and never written.
//
// pk- for the handle, sk- for the secret: the prefix is what tells a reader which
// half they are holding. Minting both under one prefix erases that distinction.
// mint issues this service account's credential and writes it where credentials
// are RESOLVED — a schema.Key row keyed to the account, the same row every other
// key in the estate lives in.
//
// It used to write AccessKey/AccessSecretHash onto the User row instead. Nothing
// reads those: store.UserByAccessKey resolves an sk- through schema.Key and
// nothing anywhere calls cred.Verify against AccessSecretHash. So a service
// account got a credential that could never authenticate — every call answered
// "API key is not recognized", which reads as revoked and was never resolvable.
// That is why they are cleared here rather than set: a second credential home
// that no resolver reads is not a safety measure, it is a dead end that looks
// like one.
//
// The secret is stored as its digest (schema.DigestSecret) and returned once, so
// the row holds nothing replayable.
func mint(ctx context.Context, db orm.DB, sa *schema.User) (key, secret string, err error) {
	key, secret = keys.Mint("pk", ""), keys.Mint("sk", "")
	// A rotate REPLACES: the deterministic name means the new credential lands on
	// the same row, so the previous secret stops resolving the moment this one is
	// written. Two live secrets for one identity is how a revoked key keeps working.
	name, now := sa.Name+"-key", time.Now().UTC().Format(time.RFC3339)
	id := sa.Owner + "/" + name
	existing, err := orm.TypedQuery[schema.Key](db).Filter("Id=", id).First()
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return "", "", zip.ErrInternal(err.Error())
	}
	if existing != nil {
		existing.AccessKey, existing.AccessSecret = key, ""
		existing.AccessSecretDigest = schema.DigestSecret(secret)
		existing.UpdatedTime = now
		if err := existing.UpdateCtx(ctx); err != nil {
			return "", "", zip.ErrInternal(err.Error())
		}
		sa.AccessKey, sa.AccessSecret, sa.AccessSecretHash = "", "", ""
		return key, secret, nil
	}
	k := orm.New[schema.Key](db)
	k.SetId(id)
	k.Owner, k.Name = sa.Owner, name
	k.DisplayName = "Service account key"
	k.Type, k.User = "User", sa.Owner+"/"+sa.Name
	k.State = "Active"
	k.AccessKey = key
	k.AccessSecretDigest = schema.DigestSecret(secret)
	k.CreatedTime, k.UpdatedTime = now, now
	if err := k.CreateCtx(ctx); err != nil {
		return "", "", zip.ErrInternal("store service account key: " + err.Error())
	}
	// The User row holds no credential material at all. See the note above.
	sa.AccessKey, sa.AccessSecret, sa.AccessSecretHash = "", "", ""
	return key, secret, nil
}

// canonical maps a (org, agent) request pair to the <org>-<agent> handle: a bare
// agent segment is prefixed, an already-canonical name is kept. Returns "" when
// the result is not a well-formed handle, so a malformed name is refused at the
// boundary rather than persisted.
func canonical(org, name string) string {
	// A service account is a user row, so its name is a USERNAME first — charset,
	// case and length come from schema.Username, the one place they are decided.
	// This file used to re-enumerate the charset itself, which is how a service
	// account could hold a name no human account could.
	full, err := schema.Username(name)
	if err != nil {
		return ""
	}
	if !boundTo(org, full) {
		// Re-checked after prefixing: binding can push a legal agent name past the
		// length bound, and the BOUND name is what gets stored.
		if full, err = schema.Username(org + "-" + full); err != nil {
			return ""
		}
	}
	if !segmented(full) {
		return ""
	}
	return full
}

// boundTo reports whether name already carries the "<org>-" prefix with a
// non-empty agent segment.
func boundTo(org, name string) bool {
	prefix := org + "-"
	return len(name) > len(prefix) && strings.HasPrefix(name, prefix)
}

// segmented reports whether name's separators are single and interior — the one
// thing a service-account handle asks for BEYOND being a valid username, which
// schema.Username has already established (so a leading separator is impossible
// here and is not re-checked). `<org>-<agent>` is a two-segment structure that
// gets read back apart, so a trailing or doubled separator would name an empty
// segment.
func segmented(name string) bool {
	if name == "" || sep(rune(name[len(name)-1])) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if sep(rune(name[i])) && sep(rune(name[i-1])) {
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

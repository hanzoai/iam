// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package compat

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/applications"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/internal/projects"
	"github.com/hanzoai/iam/internal/providers"
	"github.com/hanzoai/iam/internal/roles"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/internal/workspaces"
)

// The the legacy surface WRITE verbs (add-organization, add-user, update-user,
// update-application) the console admin BFF hard-codes, served over the SAME entity
// Create/Update logic as the REST surface — no CRUD is reimplemented here. Each is a
// TYPED zip op (not a raw handler), which is what preserves authorization: the ONE
// authz seam (app.Authorize) runs at every typed op's invoke on the DECODED input, so
// a write alias is authorized against the exact (owner, name) it will bind — a super
// for a platform-owned org/app, an org-admin for its own users — identical to the REST
// twin. The result is wrapped in the casibase {status,msg,data} envelope the clients
// parse; the data is the REDACTED entity (each Create/Update returns Mask()).
//
// Read verbs ride aliases.go; these are the "Writes ride a companion file" half.
//
// NONE of these carries an explicit operationId, and that is the rule rather than
// an omission. A legacy verb alias delegates to the canonical op; the only thing
// that distinguishes the two IS the address, so the address names it — zip's
// path-derived default (post_v1_iam_update_provider). Naming them by hand
// restated what the path already says AND collided: five of them
// (add/update/delete-provider, update/delete-organization) claimed the same id as
// the REST twin they delegate to, which OpenAPI forbids — one operationId, one
// operation — so every generated client would bind whichever it read last. The
// canonical REST op keeps the hand-picked SDK name; the alias is named for where
// it is.

// routeWrites registers the the legacy surface write-verb aliases on app. Called from Route
// (aliases.go) so reads and writes share the one Guard/Authorize seam.
//
// Each registration's prose is the comment directly above it, and that comment is
// the ONLY place it is written: zipdoc lifts it into zipdoc_gen.go, zip's spec
// derives the summary from its first sentence, and the OpenAPI description, the
// MCP tool and every generated client and CLI carry it from there. A
// WithSummary("…") beside a comment saying the same thing is two places to change
// and one to forget, so there is none — and a maintainer note in that position is
// not a note, it is what a customer reads. Where the sentence had to say
// something to US rather than to them ("console ScopeSwitcher", "the read rides
// aliases.go"), it is here instead:
//
//   - Grouping. Reads ride aliases.go; these are the writes. add-/update-/delete-
//     for organizations, users, applications, providers and roles; add-/delete-
//     only for projects and workspaces, whose reads ride
//     get-organization-projects and get-organization-workspaces.
//   - Authorization. Every one is a TYPED op, so app.Authorize runs at invoke on
//     the DECODED body — the write is authorized against the exact (owner, name)
//     it will bind, identically to its REST twin. For a project or workspace the
//     owner IS the organization, so the clause is org-admin of that org.
func routeWrites(app *zip.App, db orm.DB) {
	orgs := organizations.NewOrganizationAPI(db)
	usersAPI := users.New(db)
	appCreate, appUpdate, appDelete := applications.Create(db), applications.Update(db), applications.Delete(db)
	rolesH := roles.New(db)
	projectsH := projects.New(db)
	workspacesH := workspaces.New(db)
	provAdd, provUpdate, provDelete := providers.Add(db), providers.Update(db), providers.Delete(db)

	// Creates an organization — the account everything else in your directory
	// hangs from. Users, applications, roles, projects and workspaces are all
	// named inside one organization, so this is the first write in a new tenant.
	//
	// The older spelling of POST /v1/iam/organizations. Both reach the same
	// create, so a name already taken is refused here too.
	zip.Post(app, "/v1/iam/add-organization",
		func(ctx context.Context, in *organizations.CreateOrganizationInput) (*httpx.Response, error) {
			return envelope(orgs.Create(ctx, in))
		},
		zip.WithTags("compat"))

	// Adds a person to your organization and, if you send a password, sets the
	// one they will sign in with. The password is hashed before it is stored and
	// is never returned to you or to anyone else.
	//
	// Usernames are checked against one rule wherever an account is created —
	// this verb, password signup, a social sign-in, or SCIM — so a name accepted
	// here is a name accepted everywhere.
	//
	// The older spelling of POST /v1/iam/users, and it posts the user's fields at
	// the top level rather than wrapped in {user, password}.
	zip.Post(app, "/v1/iam/add-user",
		func(ctx context.Context, in *userBody) (*httpx.Response, error) {
			return envelope(usersAPI.Create(ctx, &users.CreateInput{User: in.User, Password: in.Password}))
		},
		zip.WithTags("compat"))

	// Updates one of your users' profile, roles or credentials. Send a password
	// to reset it; leave it out and the current one stands.
	//
	// The older spelling of POST /v1/iam/users/update, with the user's fields at
	// the top level rather than wrapped in {user, password}.
	zip.Post(app, "/v1/iam/update-user",
		func(ctx context.Context, in *userBody) (*httpx.Response, error) {
			return envelope(usersAPI.Update(ctx, &users.UpdateInput{User: in.User, Password: in.Password}))
		},
		zip.WithTags("compat"))

	// Updates one of your applications — its display, its sign-in methods and the
	// redirect URIs it is allowed to return to. Which organization and name the
	// application has are fixed when it is created and are not editable here.
	//
	// A redirect URI you add becomes an allowed sign-in origin, so this is the
	// call that makes login work from a new host.
	//
	// The older spelling of PUT /v1/iam/application.
	zip.Post(app, "/v1/iam/update-application",
		func(ctx context.Context, in *schema.Application) (*httpx.Response, error) {
			return envelope(appUpdate(ctx, in))
		},
		zip.WithTags("compat"))

	// Removes a person from your organization. Their sessions stop working and
	// the account is gone, not suspended — to keep the record and only stop
	// sign-in, update the user instead.
	//
	// The older spelling of POST /v1/iam/users/delete.
	zip.Post(app, "/v1/iam/delete-user",
		func(ctx context.Context, in *userBody) (*httpx.Response, error) {
			return envelope(usersAPI.Delete(ctx, &users.Ref{Owner: in.Owner, Name: in.Name}))
		},
		zip.WithTags("compat"))

	// Registers an application in your organization — one product or site your
	// people sign in to, with its own client credentials, sign-in methods and
	// allowed redirect URIs.
	//
	// The older spelling of POST /v1/iam/application. A name already used in the
	// organization is refused rather than overwritten.
	zip.Post(app, "/v1/iam/add-application",
		func(ctx context.Context, in *schema.Application) (*httpx.Response, error) {
			return envelope(appCreate(ctx, in))
		},
		zip.WithTags("compat"))

	// Deletes an application. Anyone mid-sign-in through it is turned away and
	// its client credentials stop working, so retire the integration first.
	//
	// The older spelling of DELETE /v1/iam/application.
	zip.Post(app, "/v1/iam/delete-application",
		func(ctx context.Context, in *schema.Application) (*httpx.Response, error) {
			return envelope(appDelete(ctx, &applications.ApplicationRef{Owner: in.Owner, Name: in.Name}))
		},
		zip.WithTags("compat"))

	// Adds an identity provider your people can sign in with, or a service your
	// applications send through — a social or enterprise login, an email or SMS
	// sender, a storage or payment connector.
	//
	// A provider is configured once here and then switched on per application, so
	// several applications can share one set of credentials.
	//
	// The older spelling of POST /v1/iam/providers.
	zip.Post(app, "/v1/iam/add-provider",
		func(ctx context.Context, in *schema.Provider) (*httpx.Response, error) {
			return envelope(provAdd(ctx, in))
		},
		zip.WithTags("compat"))

	// Updates a provider's settings or rotates the credentials it holds. The
	// change takes effect on the next sign-in through it — sessions already
	// issued are unaffected.
	//
	// The older spelling of POST /v1/iam/providers/update.
	zip.Post(app, "/v1/iam/update-provider",
		func(ctx context.Context, in *schema.Provider) (*httpx.Response, error) {
			return envelope(provUpdate(ctx, in))
		},
		zip.WithTags("compat"))

	// Removes a provider. Sign-in through it stops for every application that
	// used it, so detach those applications first if they have no other method.
	//
	// The older spelling of POST /v1/iam/providers/delete.
	zip.Post(app, "/v1/iam/delete-provider",
		func(ctx context.Context, in *schema.Provider) (*httpx.Response, error) {
			return envelope(provDelete(ctx, in))
		},
		zip.WithTags("compat"))

	// Creates a role — a named group of people that permissions are granted to.
	// Granting to a role rather than to each person is what keeps access correct
	// as your team changes: add someone to the role and they inherit everything
	// it can do.
	//
	// The older spelling of POST /v1/iam/roles.
	zip.Post(app, "/v1/iam/add-role",
		func(ctx context.Context, in *roles.Input) (*httpx.Response, error) {
			return envelope(rolesH.Create(ctx, in))
		},
		zip.WithTags("compat"))

	// Updates a role's members or the roles it includes. Access changes for
	// everyone in it as soon as the write lands.
	//
	// The older spelling of POST /v1/iam/roles/update.
	zip.Post(app, "/v1/iam/update-role",
		func(ctx context.Context, in *roles.Input) (*httpx.Response, error) {
			return envelope(rolesH.Update(ctx, in))
		},
		zip.WithTags("compat"))

	// Deletes a role. Everyone in it loses the access it carried; their accounts
	// and any other roles they hold are untouched.
	//
	// The older spelling of POST /v1/iam/roles/delete.
	zip.Post(app, "/v1/iam/delete-role",
		func(ctx context.Context, in *roles.Ref) (*httpx.Response, error) {
			return envelope(rolesH.Delete(ctx, in))
		},
		zip.WithTags("compat"))

	// Creates a project inside your organization — the scope people pick between
	// when their work is separated by product or client rather than by team.
	//
	// The older spelling of POST /v1/iam/projects. Creating one takes an
	// administrator of the owning organization.
	zip.Post(app, "/v1/iam/add-project",
		func(ctx context.Context, in *projects.Input) (*httpx.Response, error) {
			return envelope(projectsH.Create(ctx, in))
		},
		zip.WithTags("compat"))

	// Deletes a project. The people and roles in your organization are unchanged;
	// what goes is the scope itself, so anything addressed by it must move first.
	//
	// The older spelling of POST /v1/iam/projects/delete.
	zip.Post(app, "/v1/iam/delete-project",
		func(ctx context.Context, in *projects.Ref) (*httpx.Response, error) {
			return envelope(projectsH.Delete(ctx, in))
		},
		zip.WithTags("compat"))

	// Creates a workspace inside your organization — the scope a team works in,
	// alongside projects rather than instead of them.
	//
	// The older spelling of POST /v1/iam/workspaces. Creating one takes an
	// administrator of the owning organization.
	zip.Post(app, "/v1/iam/add-workspace",
		func(ctx context.Context, in *workspaces.Input) (*httpx.Response, error) {
			return envelope(workspacesH.Create(ctx, in))
		},
		zip.WithTags("compat"))

	// Deletes a workspace. The people and roles in your organization are
	// unchanged; what goes is the scope itself.
	//
	// The older spelling of POST /v1/iam/workspaces/delete.
	zip.Post(app, "/v1/iam/delete-workspace",
		func(ctx context.Context, in *workspaces.Ref) (*httpx.Response, error) {
			return envelope(workspacesH.Delete(ctx, in))
		},
		zip.WithTags("compat"))

	// Updates your organization — its display, its default settings and the
	// sign-in rules everyone in it inherits.
	//
	// The older spelling of POST /v1/iam/organizations/update.
	zip.Post(app, "/v1/iam/update-organization",
		func(ctx context.Context, in *organizations.UpdateOrganizationInput) (*httpx.Response, error) {
			return envelope(orgs.Update(ctx, in))
		},
		zip.WithTags("compat"))

	// Deletes an organization and everything named inside it — its users,
	// applications, roles, projects and workspaces. There is no undo, and every
	// session issued under it stops working.
	//
	// The older spelling of POST /v1/iam/organizations/delete.
	zip.Post(app, "/v1/iam/delete-organization",
		func(ctx context.Context, in *organizations.DeleteOrganizationInput) (*httpx.Response, error) {
			return envelope(orgs.Delete(ctx, in))
		},
		zip.WithTags("compat"))
}

// userBody is the bare-user body the the legacy surface add-user/update-user verbs post (the
// user's fields at top level, plus an optional plaintext password), distinct from the
// REST twin's {user,password} envelope. It embeds schema.User so the authz op-seam
// reads the target (Owner, Name) straight off it, then the handler hands the parts to
// the ONE users Create/Update path (which bcrypt-hashes the password — never stored
// plaintext — and returns the redacted row).
type userBody struct {
	schema.User
	Password string `json:"password,omitempty"`
}

// envelope wraps an entity Create/Update result in the casibase Response the the legacy surface
// clients parse: {status:"ok", data:<masked entity>} on success, or a 200
// {status:"error", msg} on a handler error (the casibase convention — clients branch
// on status, not the HTTP code), never an HTTP error status. An authorization refusal
// happens earlier, at the op-seam, and surfaces as a 403 the clients already handle.
func envelope[T any](entity *T, err error) (*httpx.Response, error) {
	if err != nil {
		return &httpx.Response{Status: "error", Msg: err.Error()}, nil
	}
	return &httpx.Response{Status: "ok", Data: entity}, nil
}

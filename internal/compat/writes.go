// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package compat

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/applications"
	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/organizations"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/users"
)

// The Casdoor WRITE verbs (add-organization, add-user, update-user,
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

// routeWrites registers the Casdoor write-verb aliases on app. Called from Route
// (aliases.go) so reads and writes share the one Guard/Authorize seam.
func routeWrites(app *zip.App, db orm.DB) {
	orgs := organizations.NewOrganizationAPI(db)
	usersAPI := users.New(db)
	appUpdate := applications.Update(db)

	zip.Post(app, "/v1/iam/add-organization",
		func(ctx context.Context, in *organizations.CreateOrganizationInput) (*httpx.Response, error) {
			return envelope(orgs.Create(ctx, in))
		},
		zip.WithOperationID("addOrganization"), zip.WithSummary("Create an organization (Casdoor verb)"), zip.WithTags("compat"))

	zip.Post(app, "/v1/iam/add-user",
		func(ctx context.Context, in *userBody) (*httpx.Response, error) {
			return envelope(usersAPI.Create(ctx, &users.CreateInput{User: in.User, Password: in.Password}))
		},
		zip.WithOperationID("addUser"), zip.WithSummary("Create a user (Casdoor verb)"), zip.WithTags("compat"))

	zip.Post(app, "/v1/iam/update-user",
		func(ctx context.Context, in *userBody) (*httpx.Response, error) {
			return envelope(usersAPI.Update(ctx, &users.UpdateInput{User: in.User, Password: in.Password}))
		},
		zip.WithOperationID("updateUser"), zip.WithSummary("Update a user (Casdoor verb)"), zip.WithTags("compat"))

	zip.Post(app, "/v1/iam/update-application",
		func(ctx context.Context, in *schema.Application) (*httpx.Response, error) {
			return envelope(appUpdate(ctx, in))
		},
		zip.WithOperationID("updateApplication"), zip.WithSummary("Update an application (Casdoor verb)"), zip.WithTags("compat"))
}

// userBody is the bare-user body the Casdoor add-user/update-user verbs post (the
// user's fields at top level, plus an optional plaintext password), distinct from the
// REST twin's {user,password} envelope. It embeds schema.User so the authz op-seam
// reads the target (Owner, Name) straight off it, then the handler hands the parts to
// the ONE users Create/Update path (which bcrypt-hashes the password — never stored
// plaintext — and returns the redacted row).
type userBody struct {
	schema.User
	Password string `json:"password,omitempty"`
}

// envelope wraps an entity Create/Update result in the casibase Response the Casdoor
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

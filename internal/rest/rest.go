// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package rest is the ONE way an IAM entity is bound to HTTP.
//
// Every entity is a resource at /v1/iam/<resource>, addressed by the pair
// (owner, name) that IS its identity in the store — orm keys every row by the
// string "owner/name". So the member URL carries BOTH halves as path segments:
//
//	GET    /v1/iam/<resource>                list
//	POST   /v1/iam/<resource>                create
//	GET    /v1/iam/<resource>/{owner}/{name} read
//	PATCH  /v1/iam/<resource>/{owner}/{name} update
//	PUT    /v1/iam/<resource>/{owner}/{name} update
//	DELETE /v1/iam/<resource>/{owner}/{name} delete
//
// TWO segments, not one encoded segment: Go decodes %2F back to "/" in
// URL.Path before routing, so an escaped composite key matches no route at all.
// The honest REST spelling of a composite key is the only one that works.
//
// The verb is the HTTP method, where it belongs. It replaces three dialects that
// had accumulated — POST /<resource>/get, singular-noun /<resource> with real
// verbs, and the Casdoor get-<resource> compound — with one.
//
// WHY A HELPER AND NOT A TABLE: `ai` generates its routes from a declarative
// table because beego dispatches by method NAME, so a table of strings suffices.
// zip handlers are statically typed and each entity's In/Out types differ, so a
// heterogeneous table would have to erase those types and lose exactly the
// checking that makes the typed surface worth having. Generic functions keep the
// types and still leave one place where the shape is decided: change the member
// URL here and every entity moves together.
//
// Registration must happen AFTER the authz Guard is mounted (see internal/routes)
// — these are typed ops, so each also passes the app-wide Authorize hook on its
// decoded input, whose (owner, name) the path params bind.
package rest

import (
	"github.com/zap-proto/zip"
)

// path returns the member URL for a resource. The param NAMES are load-bearing:
// zip binds them onto the decoded input's `owner`/`name` json fields, and the
// authorization seam reads its target from those same fields.
func path(resource string) string { return "/v1/iam/" + resource + "/:owner/:name" }

// Collection registers the collection surface: list and create.
//
// List is a GET, so it carries no body; create is a POST of the new record.
func Collection[ListIn, ListOut, CreateIn, Obj any](
	app *zip.App, resource string,
	list zip.TypedHandler[ListIn, ListOut],
	create zip.TypedHandler[CreateIn, Obj],
) {
	url := "/v1/iam/" + resource
	zip.Get(app, url, list, zip.WithTags(resource), zip.WithSummary("List "+resource))
	zip.Post(app, url, create, zip.WithTags(resource), zip.WithSummary("Create a "+resource+" entry"))
}

// Member registers the member surface at /v1/iam/<resource>/{owner}/{name}:
// read, update, delete.
//
// PUT is registered alongside PATCH and reaches the SAME handler. Every IAM
// update handler already takes a whole record and overlays it onto the stored
// row, so a full replacement and a partial update are not distinct operations
// here; refusing PUT would advertise a distinction the implementation does not
// make.
func Member[Ref, Obj, UpdateIn, DelOut any](
	app *zip.App, resource string,
	read zip.TypedHandler[Ref, Obj],
	update zip.TypedHandler[UpdateIn, Obj],
	del zip.TypedHandler[Ref, DelOut],
) {
	url := path(resource)
	one := "a " + resource + " entry"
	zip.Get(app, url, read, zip.WithTags(resource), zip.WithSummary("Get "+one))
	zip.Patch(app, url, update, zip.WithTags(resource), zip.WithSummary("Update "+one))
	zip.Put(app, url, update, zip.WithTags(resource), zip.WithSummary("Replace "+one))
	zip.Delete(app, url, del, zip.WithTags(resource), zip.WithSummary("Delete "+one))
}

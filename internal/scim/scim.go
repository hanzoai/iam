// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package scim serves the SCIM 2.0 protocol (RFC 7644) over iam's identity store
// — the STANDARD identity-provisioning surface that replaces the the legacy surface entity
// verbs (the retired get-users/add-user/update-user/delete-user, …) per HIP-0111. There are
// no "verbs": creating an identity is POST /Users, reading is GET, updating is
// PUT/PATCH (RFC 7644 §3.5.2), removing is DELETE — plain HTTP on a resource.
//
// Authorization: the SCIM subtree is authenticated by authz.Guard (a bearer is
// required) but path-authorized — the target rides in the path, not the query, so
// each handler scopes the caller through principal.Scope (a SuperAdmin may act across
// tenants; everyone else is pinned to its own org). Secrets never cross a SCIM
// response: every user is projected through schema.User.Mask() and the write-only
// `password` is never echoed. The response envelopes are the SCIM standard ones
// (ListResponse, Error), never the the legacy surface {status,data,data2}.
package scim

import (
	"context"
	"encoding/json"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"
)

// The SCIM 2.0 URNs and paths this service implements.
const (
	base = "/v1/iam/scim/v2"

	schemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatchOp      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaHanzoUserExt = "urn:ietf:params:scim:schemas:extension:hanzo:2.0:User"
	schemaSPConfig     = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

	// contentTypeSCIM is what RFC 7644 §3.1 asks a SCIM response to carry, and it
	// does not reach the wire. The helpers below set it and then write the body
	// with fiber's Res.JSON, which takes an OPTIONAL content type and, given none,
	// overwrites the header with application/json; charset=utf-8 — so every SCIM
	// response, discovery and /Users alike, has always answered that instead.
	// Measured, not inferred: TestDiscovery_contentTypeIsTheSurfaces pins it.
	//
	// Correcting it means changing how the BODY is written on both halves at once
	// (a typed op has no hook — zip owns the JSON call), which is a change to the
	// surface and not to these five routes. Until then this reads as a statement
	// of intent; do not read it as a description of the wire.
	contentTypeSCIM = "application/scim+json"
)

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the SCIM 2.0 surface on app.
//
// Discovery (RFC 7644 §4) — /ServiceProviderConfig here, /Schemas and
// /ResourceTypes in routeDiscovery — is what an IdP reads BEFORE it provisions:
// static protocol metadata, the same for every tenant, answered out of package
// variables and never out of the store. All five are TYPED ops, so they are in
// the OpenAPI document, the MCP tool list and every generated client, instead of
// being five addresses only a hand-written integration could find.
//
// Their inputs name no Owner and no Name — the two fields the op-invoke
// authorizer reads reflectively as the target it must authorize (authz.Authorize
// → decodedTarget). A discovery document belongs to no tenant, so it decodes to
// an empty target and the read is admitted, which is the same conclusion the
// Guard already reached for the raw handlers these replace.
//
// The /Users CRUD below stays raw on purpose: it binds a two-segment path id,
// re-scopes every call through principal.Scope, and answers RFC 7644 §3.12 Errors
// from a dozen branches.
func Route(app *zip.App, db orm.DB) {
	// Tells your identity provider which parts of SCIM this
	// directory supports, so it configures itself instead of you filling in a form.
	//
	// Filtering and partial updates are supported. Bulk operations, sorting and
	// entity tags are not — an IdP that reads this will not attempt them.
	zip.Get[nothing, config](app, base+"/ServiceProviderConfig",
		func(context.Context, *nothing) (*config, error) { return &capabilities, nil },
		zip.WithStatus(200), zip.WithTags("scim"))
	routeDiscovery(app)

	// Users resource. The item path is {owner}/{name} because the SCIM id is
	// "owner/name" (iam's natural key) and a client appends that opaque id
	// verbatim — two segments, so no slash-in-id percent-encoding ambiguity.
	app.Get(base+"/Users", listUsers(db))
	app.Post(base+"/Users", createUser(db))
	app.Get(base+"/Users/:owner/:name", getUser(db))
	app.Put(base+"/Users/:owner/:name", replaceUser(db))
	app.Patch(base+"/Users/:owner/:name", patchUser(db))
	app.Delete(base+"/Users/:owner/:name", deleteUser(db))
}

// listResponse is the SCIM ListResponse envelope (RFC 7644 §3.4.2).
type listResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// page is the ListResponse as a VALUE — what a typed op returns, where scimList
// writes it through a Ctx. One constructor, so the envelope cannot be spelled two
// ways: a resource set is never null on the wire (an empty page carries [], which
// is what a client iterating Resources needs).
func page(total, startIndex, perPage int, resources []any) *listResponse {
	if resources == nil {
		resources = []any{}
	}
	return &listResponse{
		Schemas:      []string{schemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: perPage,
		Resources:    resources,
	}
}

// scimList writes a ListResponse (see contentTypeSCIM on the header).
func scimList(c *zip.Ctx, total, startIndex, perPage int, resources []any) error {
	c.SetHeader("Content-Type", contentTypeSCIM)
	return c.JSON(200, page(total, startIndex, perPage, resources))
}

// scimJSON writes a resource (see contentTypeSCIM on the header).
func scimJSON(c *zip.Ctx, status int, v any) error {
	c.SetHeader("Content-Type", contentTypeSCIM)
	return c.JSON(status, v)
}

// fault is the SCIM Error envelope (RFC 7644 §3.12) as a VALUE. `status` is a
// STRING there, and it restates the HTTP status — a client that reads only the
// body still learns what happened.
//
// The field order is the order this envelope has always reached the wire: it was
// a map[string]any, and encoding/json sorts a map's keys. Fixing it in a struct
// changes no byte and takes the ordering off the encoder, which is not a promise
// every JSON implementation makes.
type fault struct {
	Detail  string   `json:"detail"`
	Schemas []string `json:"schemas"`
	Type    string   `json:"scimType,omitempty"`
	Status  string   `json:"status"`
}

// refuse builds the SCIM Error for an HTTP status. scimType is optional (e.g.
// "invalidValue", "uniqueness", "mutability"). ONE constructor: a raw handler
// writes it through a Ctx, a typed op returns it as its answer, and neither can
// drift from the other about the shape.
func refuse(status int, detail, scimType string) fault {
	return fault{Detail: detail, Schemas: []string{schemaError}, Type: scimType, Status: itoa(status)}
}

// scimError writes the SCIM Error envelope under the HTTP status it names.
func scimError(c *zip.Ctx, status int, detail, scimType string) error {
	c.SetHeader("Content-Type", contentTypeSCIM)
	return c.JSON(status, refuse(status, detail, scimType))
}

// nothing is the input of an op that reads none. A discovery document is the same
// for every caller, so there is no field for a request to bind — and, deliberately,
// no Owner and no Name for the op-invoke authorizer to read as a tenant target.
type nothing struct{}

// answer is a discovery reply that is EITHER the document asked for or the SCIM
// Error saying this service does not publish it. Two documents, one Out type,
// because a typed op has one Out and the alternative — returning a Go error — is
// zip's {status,code,error} envelope, which is not what an RFC 7644 client parses.
//
// It writes its own JSON, so the caller receives the document itself and not a
// wrapper around it. Its published schema is therefore "any JSON", which is the
// only true thing to say about a union of two shapes.
type answer struct {
	doc  any
	code int
}

// StatusCode is [zip.StatusCoder]: the status this answer rides on, 200 when it
// names none.
func (a *answer) StatusCode() int {
	if a.code == 0 {
		return 200
	}
	return a.code
}

// MarshalJSON writes the document alone.
func (a *answer) MarshalJSON() ([]byte, error) { return json.Marshal(a.doc) }

// missing is the answer for a discovery document this service does not publish:
// the SCIM Error, under the status it names. The status is written once — the
// body restates it (RFC 7644 §3.12), and the two disagreeing is precisely what a
// client cannot recover from.
func missing(detail string) *answer {
	return &answer{doc: refuse(404, detail, ""), code: 404}
}

// config is the ServiceProviderConfig document (RFC 7643 §5).
//
// Its fields are alphabetical for the same reason fault's are: that is the order
// this document has always reached the wire, from a map encoding/json sorted.
type config struct {
	Schemes  []scheme `json:"authenticationSchemes"`
	Bulk     bulk     `json:"bulk"`
	Password toggle   `json:"changePassword"`
	Docs     string   `json:"documentationUri"`
	Etag     toggle   `json:"etag"`
	Filter   filter   `json:"filter"`
	Patch    toggle   `json:"patch"`
	Schemas  []string `json:"schemas"`
	Sort     toggle   `json:"sort"`
}

// toggle is a capability this service either has or has not.
type toggle struct {
	Supported bool `json:"supported"`
}

// bulk is the bulk-operation capability and the ceilings that would bound it.
type bulk struct {
	Operations int  `json:"maxOperations"`
	Payload    int  `json:"maxPayloadSize"`
	Supported  bool `json:"supported"`
}

// filter is the filtering capability and the most results one page may carry.
type filter struct {
	Results   int  `json:"maxResults"`
	Supported bool `json:"supported"`
}

// scheme is one way a client may authenticate to this surface.
type scheme struct {
	Description string `json:"description"`
	Name        string `json:"name"`
	Primary     bool   `json:"primary"`
	Type        string `json:"type"`
}

// capabilities is what this service supports, stated once: it does not vary by
// caller, by tenant or by request, so it is a value and not a function.
//
// Every `supported` is written out, including the false ones. A discovery
// document's job is to say what an IdP must NOT attempt, so "we do not do bulk"
// is the content, not an omission Go's zero value happens to produce.
var capabilities = config{
	Schemes: []scheme{{
		Description: "Authentication via an OAuth 2.0 bearer access token (HIP-0111).",
		Name:        "OAuth Bearer Token",
		Primary:     true,
		Type:        "oauthbearertoken",
	}},
	Bulk:     bulk{Operations: 0, Payload: 0, Supported: false},
	Password: toggle{Supported: true},
	Docs:     "https://github.com/hanzoai/hips/blob/main/HIPs/hip-0111-iam-authentication-standard.md",
	Etag:     toggle{Supported: false},
	Filter:   filter{Results: scimMaxResults, Supported: true},
	Patch:    toggle{Supported: true},
	Schemas:  []string{schemaSPConfig},
	Sort:     toggle{Supported: false},
}

// itoa is a tiny int→string without importing strconv at every call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

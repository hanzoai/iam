// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package scim

// SCIM discovery (RFC 7644 §4): /Schemas and /ResourceTypes, beside the
// /ServiceProviderConfig this service already serves. An IdP reads these BEFORE
// it provisions, to learn which attributes exist and which it may write; without
// them a connector either refuses to configure or guesses and sends attributes
// this service will not honour.
//
// The attribute table below is the ONE description of the User resource. It is
// not a second, hand-kept copy of the wire shape: TestSchema_matchesWireStruct
// reflects over scimUser and fails the gate if the two ever diverge, in either
// direction. So "what the schema advertises" and "what the handler binds" cannot
// drift apart silently — the usual failure of a hand-written discovery document.
//
// Mutability is load-bearing here, not decoration. `userType` is advertised
// readOnly because schema.User.Type is the identity-class discriminator
// (service-account); RFC 7643 §7 says a readOnly attribute in a write is ignored,
// which is exactly what applyToUser does. `password` is writeOnly: accepted, never
// returned.

import "github.com/zap-proto/zip"

// attribute is one SCIM attribute definition (RFC 7643 §7).
type attribute struct {
	Name          string      `json:"name"`
	Type          string      `json:"type"`
	MultiValued   bool        `json:"multiValued"`
	Description   string      `json:"description,omitempty"`
	Required      bool        `json:"required"`
	CaseExact     bool        `json:"caseExact"`
	Mutability    string      `json:"mutability"`
	Returned      string      `json:"returned"`
	Uniqueness    string      `json:"uniqueness,omitempty"`
	SubAttributes []attribute `json:"subAttributes,omitempty"`
}

// rw builds a plain read/write single-valued string attribute.
func rw(name, desc string) attribute {
	return attribute{Name: name, Type: "string", Mutability: "readWrite", Returned: "default", Description: desc}
}

// valueSub is the `value` sub-attribute every multi-valued contact field carries.
var valueSub = []attribute{
	rw("value", "The attribute's significant value."),
	rw("type", "A label indicating the value's function."),
	{Name: "primary", Type: "boolean", Mutability: "readWrite", Returned: "default",
		Description: "The preferred value among a multi-valued set."},
}

// userAttributes describes the User resource EXACTLY as this service implements
// it — the attributes internal/scim binds, and no others.
var userAttributes = []attribute{
	{Name: "userName", Type: "string", Required: true, Mutability: "immutable", Returned: "default",
		Uniqueness: "server", Description: "Unique identifier for the user within its owning organization."},
	{Name: "name", Type: "complex", Mutability: "readWrite", Returned: "default",
		Description: "The components of the user's name.",
		SubAttributes: []attribute{
			rw("givenName", "The given name."),
			rw("familyName", "The family name."),
			rw("formatted", "The full name, formatted for display."),
		}},
	rw("displayName", "The name to display for the user."),
	rw("profileUrl", "A URI of the user's profile page."),
	{Name: "userType", Type: "string", Mutability: "readOnly", Returned: "default",
		Description: "The identity class of the account (e.g. service-account). Server-assigned: it is set through the service-account surface, never by a provisioning write."},
	{Name: "emails", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default",
		Description: "Email addresses for the user.", SubAttributes: valueSub},
	{Name: "phoneNumbers", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default",
		Description: "Phone numbers for the user.", SubAttributes: valueSub},
	{Name: "photos", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default",
		Description: "URIs of images for the user.", SubAttributes: valueSub},
	{Name: "addresses", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default",
		Description: "Physical mailing addresses for the user. One address is persisted; a multi-valued write collapses to the primary.",
		SubAttributes: []attribute{
			rw("locality", "The city or locality."),
			rw("region", "The state or region."),
			rw("country", "The ISO 3166-1 alpha-2 country code."),
			rw("type", "A label indicating the address's function."),
			{Name: "primary", Type: "boolean", Mutability: "readWrite", Returned: "default",
				Description: "The preferred address among a multi-valued set."},
		}},
	{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default",
		Description: "Whether the user may authenticate. Defaults to true."},
	{Name: "password", Type: "string", Mutability: "writeOnly", Returned: "never",
		Description: "The user's cleartext password, accepted on write only. It is hashed once by the core and never returned."},
}

// hanzoExtAttributes describes the Hanzo extension: the tenancy and privilege
// facts SCIM's own schemas have no place for.
//
// `owner` is the TENANT. It is deliberately here and NOT the standard enterprise
// extension's `organization`, which RFC 7643 §4.3 defines as free text naming
// where a person works — an IdP-controlled label, not an authorization key.
// Whatever a client sends, authz.Scope re-derives the tenant from the caller, so
// this attribute can narrow a SuperAdmin's write but never widen anyone's.
var hanzoExtAttributes = []attribute{
	{Name: "owner", Type: "string", Required: true, Mutability: "immutable", Returned: "default",
		Description: "The organization that owns the user — the tenant. Always re-scoped to the caller's authorization; a non-SuperAdmin may only name its own."},
	{Name: "isAdmin", Type: "boolean", Mutability: "readWrite", Returned: "default",
		Description: "Whether the user administers its organization. Settable only by a SuperAdmin."},
}

// schemaDoc is the SCIM Schema resource (RFC 7643 §7).
type schemaDoc struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Attributes  []attribute `json:"attributes"`
	Meta        meta        `json:"meta"`
}

// meta is the resource metadata every discovery document carries.
type meta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location"`
}

const schemaListSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema"

// schemas is the set this service publishes, in one place so the list and the
// item endpoints cannot disagree.
var schemas = []schemaDoc{
	{
		Schemas: []string{schemaListSchema}, ID: schemaUser, Name: "User",
		Description: "User Account",
		Attributes:  userAttributes,
		Meta:        meta{ResourceType: "Schema", Location: base + "/Schemas/" + schemaUser},
	},
	{
		Schemas: []string{schemaListSchema}, ID: schemaHanzoUserExt, Name: "HanzoUser",
		Description: "Hanzo tenancy and privilege extension to the User schema",
		Attributes:  hanzoExtAttributes,
		Meta:        meta{ResourceType: "Schema", Location: base + "/Schemas/" + schemaHanzoUserExt},
	},
}

// resourceTypeDoc is the SCIM ResourceType resource (RFC 7643 §6).
type resourceTypeDoc struct {
	Schemas          []string          `json:"schemas"`
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Endpoint         string            `json:"endpoint"`
	Description      string            `json:"description"`
	Schema           string            `json:"schema"`
	SchemaExtensions []schemaExtension `json:"schemaExtensions,omitempty"`
	Meta             meta              `json:"meta"`
}

type schemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

const resourceTypeSchema = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"

// resourceTypes is the set this service publishes. One resource: User.
var resourceTypes = []resourceTypeDoc{{
	Schemas: []string{resourceTypeSchema}, ID: "User", Name: "User",
	Endpoint: "/Users", Description: "User Account in Hanzo IAM", Schema: schemaUser,
	SchemaExtensions: []schemaExtension{{Schema: schemaHanzoUserExt, Required: true}},
	Meta:             meta{ResourceType: "ResourceType", Location: base + "/ResourceTypes/User"},
}}

// routeDiscovery registers the discovery subtree. These documents are the same
// for every tenant — static protocol metadata carrying no identity data — so they
// are authenticated (the Guard covers the whole /v1/iam/scim/ subtree) but not
// org-scoped, exactly like /ServiceProviderConfig.
func routeDiscovery(app *zip.App) {
	app.Get(base+"/Schemas", listSchemas)
	app.Get(base+"/Schemas/:id", getSchema)
	app.Get(base+"/ResourceTypes", listResourceTypes)
	app.Get(base+"/ResourceTypes/:name", getResourceType)
}

// listSchemas returns the attribute definitions this directory understands, so
// your identity provider knows which fields it may send and what they mean
// before it sends any.
func listSchemas(c *zip.Ctx) error {
	out := make([]any, 0, len(schemas))
	for _, s := range schemas {
		out = append(out, s)
	}
	return scimList(c, len(out), 1, len(out), out)
}

// getSchema returns one attribute definition in full.
func getSchema(c *zip.Ctx) error {
	id := c.Param("id")
	for _, s := range schemas {
		if s.ID == id {
			return scimJSON(c, 200, s)
		}
	}
	return scimError(c, 404, "Schema "+id+" not found", "")
}

// listResourceTypes returns the kinds of record this directory provisions and
// the address of each, so your identity provider discovers them rather than
// having them configured by hand.
func listResourceTypes(c *zip.Ctx) error {
	out := make([]any, 0, len(resourceTypes))
	for _, r := range resourceTypes {
		out = append(out, r)
	}
	return scimList(c, len(out), 1, len(out), out)
}

// getResourceType returns one provisionable record kind in full.
func getResourceType(c *zip.Ctx) error {
	name := c.Param("name")
	for _, r := range resourceTypes {
		if r.Name == name {
			return scimJSON(c, 200, r)
		}
	}
	return scimError(c, 404, "ResourceType "+name+" not found", "")
}

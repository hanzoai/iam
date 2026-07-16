// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package scim serves the SCIM 2.0 protocol (RFC 7644) over iam2's identity store
// — the STANDARD identity-provisioning surface that replaces the Casdoor entity
// verbs (get-users/add-user/update-user/delete-user, …) per HIP-0111. There are
// no "verbs": creating an identity is POST /Users, reading is GET, updating is
// PUT/PATCH (RFC 7644 §3.5.2), removing is DELETE — plain HTTP on a resource.
//
// Authorization: the SCIM subtree is authenticated by authz.Guard (a bearer is
// required) but path-authorized — the target rides in the path, not the query, so
// each handler scopes the caller through authz.Scope (a SuperAdmin may act across
// tenants; everyone else is pinned to its own org). Secrets never cross a SCIM
// response: every user is projected through schema.User.Mask() and the write-only
// `password` is never echoed. The response envelopes are the SCIM standard ones
// (ListResponse, Error), never the Casdoor {status,data,data2}.
package scim

import (
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

	contentTypeSCIM = "application/scim+json"
)

// Route registers the SCIM 2.0 surface on app.
func Route(app *zip.App, db orm.DB) {
	// Discovery.
	app.Get(base+"/ServiceProviderConfig", serviceProviderConfig)

	// Users resource. The item path is {owner}/{name} because the SCIM id is
	// "owner/name" (iam2's natural key) and a client appends that opaque id
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

// scimList writes a ListResponse with the SCIM content type.
func scimList(c *zip.Ctx, total, startIndex, perPage int, resources []any) error {
	c.SetHeader("Content-Type", contentTypeSCIM)
	if resources == nil {
		resources = []any{}
	}
	return c.JSON(200, listResponse{
		Schemas:      []string{schemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: perPage,
		Resources:    resources,
	})
}

// scimJSON writes a resource with the SCIM content type.
func scimJSON(c *zip.Ctx, status int, v any) error {
	c.SetHeader("Content-Type", contentTypeSCIM)
	return c.JSON(status, v)
}

// scimError writes the SCIM Error envelope (RFC 7644 §3.12) with the HTTP status.
// scimType is optional (e.g. "invalidValue", "uniqueness", "mutability").
func scimError(c *zip.Ctx, status int, detail, scimType string) error {
	c.SetHeader("Content-Type", contentTypeSCIM)
	body := map[string]any{
		"schemas": []string{schemaError},
		"detail":  detail,
		"status":  itoa(status),
	}
	if scimType != "" {
		body["scimType"] = scimType
	}
	return c.JSON(status, body)
}

// serviceProviderConfig advertises the features this SCIM service supports
// (RFC 7644 §5). Filtering + PATCH are supported; bulk + ETag + sort are not.
func serviceProviderConfig(c *zip.Ctx) error {
	return scimJSON(c, 200, map[string]any{
		"schemas":          []string{schemaSPConfig},
		"documentationUri": "https://github.com/hanzoai/hips/blob/main/HIPs/hip-0111-iam-authentication-standard.md",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": scimMaxResults},
		"changePassword":   map[string]any{"supported": true},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "Authentication via an OAuth 2.0 bearer access token (HIP-0111).",
			"primary":     true,
		}},
	})
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

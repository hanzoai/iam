// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package scim

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
	"github.com/hanzoai/iam2/internal/users"
)

// decodeSCIM unmarshals the raw request body into v, independent of Content-Type:
// SCIM clients send `application/scim+json`, which a content-type-dispatching body
// parser may not recognize as JSON. The body IS JSON (RFC 7644 §3.1), so parse it
// as such directly.
func decodeSCIM(c *zip.Ctx, v any) error {
	body := c.Body()
	if len(body) == 0 {
		return errors.New("empty request body")
	}
	return json.Unmarshal(body, v)
}

const (
	scimMaxResults     = 200 // hard cap on a page, whatever count is asked
	scimDefaultPerPage = 100
)

// scimUser is the SCIM 2.0 core User (RFC 7643 §4.1) plus a Hanzo extension for
// the tenant owner + admin flag. It backs both request and response; the
// write-only `password` is zeroed before any response is written.
type scimUser struct {
	Schemas      []string          `json:"schemas"`
	ID           string            `json:"id,omitempty"`
	ExternalID   string            `json:"externalId,omitempty"`
	UserName     string            `json:"userName"`
	Name         *scimName         `json:"name,omitempty"`
	DisplayName  string            `json:"displayName,omitempty"`
	Emails       []scimMultiValued `json:"emails,omitempty"`
	PhoneNumbers []scimMultiValued `json:"phoneNumbers,omitempty"`
	Photos       []scimMultiValued `json:"photos,omitempty"`
	Active       bool              `json:"active"`
	Password     string            `json:"password,omitempty"`
	Hanzo        *hanzoUserExt     `json:"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User,omitempty"`
	Meta         *scimMeta         `json:"meta,omitempty"`
}

type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimMultiValued struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type hanzoUserExt struct {
	Owner   string `json:"owner,omitempty"`
	IsAdmin bool   `json:"isAdmin,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

// toSCIM projects a stored user (already Mask()ed by the caller) into a SCIM User.
// The SCIM id is the natural key "owner/name"; owner + isAdmin ride the Hanzo
// extension. No credential material is present (Mask stripped it; password is
// write-only and never set here).
func toSCIM(u *schema.User) *scimUser {
	s := &scimUser{
		Schemas:     []string{schemaUser, schemaHanzoUserExt},
		ID:          u.Owner + "/" + u.Name,
		UserName:    u.Name,
		DisplayName: u.DisplayName,
		Active:      !u.IsForbidden && !u.IsDeleted,
		Hanzo:       &hanzoUserExt{Owner: u.Owner, IsAdmin: u.IsAdmin},
		Meta: &scimMeta{
			ResourceType: "User",
			Created:      u.CreatedTime,
			LastModified: u.UpdatedTime,
			Location:     base + "/Users/" + u.Owner + "/" + u.Name,
		},
	}
	if u.FirstName != "" || u.LastName != "" {
		s.Name = &scimName{GivenName: u.FirstName, FamilyName: u.LastName}
	}
	if u.Email != "" {
		s.Emails = []scimMultiValued{{Value: u.Email, Primary: true, Type: "work"}}
	}
	if u.Phone != "" {
		s.PhoneNumbers = []scimMultiValued{{Value: u.Phone, Primary: true, Type: "work"}}
	}
	if u.Avatar != "" {
		s.Photos = []scimMultiValued{{Value: u.Avatar, Type: "photo"}}
	}
	return s
}

// applyToUser overlays a SCIM User's mutable attributes onto a schema.User (used
// by create + replace). It never sets identity (owner/name) — the caller binds
// those from the scoped path/body — and never sets credential fields other than
// through the returned plaintext password.
func applyToUser(in *scimUser, u *schema.User) (password string) {
	u.DisplayName = in.DisplayName
	if in.Name != nil {
		u.FirstName, u.LastName = in.Name.GivenName, in.Name.FamilyName
	}
	u.Email = primaryValue(in.Emails)
	u.Phone = primaryValue(in.PhoneNumbers)
	if v := primaryValue(in.Photos); v != "" {
		u.Avatar = v
	}
	// active=false soft-disables (IsForbidden); active=true clears it.
	u.IsForbidden = !in.Active
	if in.Hanzo != nil {
		u.IsAdmin = in.Hanzo.IsAdmin
	}
	return in.Password
}

// primaryValue returns the primary multi-valued entry's value, or the first.
func primaryValue(vs []scimMultiValued) string {
	if len(vs) == 0 {
		return ""
	}
	for _, v := range vs {
		if v.Primary {
			return v.Value
		}
	}
	return vs[0].Value
}

// listUsers serves GET /Users — owner-scoped, filterable by `userName eq "x"` /
// `emails eq "x"`, paginated (startIndex 1-based, count).
func listUsers(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, err := authz.Scope(ctx, c.Query("owner"))
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		q := orm.TypedQuery[schema.User](db)
		if owner != "" {
			q = q.Filter("Owner=", owner)
		}
		if field, value, ok := parseEqFilter(c.Query("filter")); ok {
			switch field {
			case "username":
				q = q.Filter("Name=", value)
			case "emails", "emails.value":
				q = q.Filter("Email=", value)
			default:
				// An unsupported filter attribute is a client error, not a silent
				// full-table return (RFC 7644 §3.4.2.2).
				return scimError(c, 400, "unsupported filter attribute: "+field, "invalidFilter")
			}
		}

		total, err := q.Count(ctx)
		if err != nil {
			return scimError(c, 500, err.Error(), "")
		}
		startIndex, perPage := pageParams(c)
		rows, err := q.Order("Name").Limit(perPage).Offset(startIndex - 1).GetAll(ctx)
		if err != nil {
			return scimError(c, 500, err.Error(), "")
		}
		resources := make([]any, 0, len(rows))
		for _, u := range rows {
			resources = append(resources, toSCIM(u.Mask()))
		}
		return scimList(c, total, startIndex, len(resources), resources)
	}
}

// getUser serves GET /Users/{owner}/{name}.
func getUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, err := scopedTarget(c)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		u, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return scimError(c, 500, err.Error(), "")
		}
		if u == nil {
			return scimError(c, 404, "User "+owner+"/"+name+" not found", "")
		}
		return scimJSON(c, 200, toSCIM(u.Mask()))
	}
}

// createUser serves POST /Users. The tenant owner is the scoped owner (a non-super
// creates in its own org; a super must name one via the Hanzo extension `owner`).
func createUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		var in scimUser
		if err := decodeSCIM(c, &in); err != nil {
			return scimError(c, 400, "invalid SCIM body: "+err.Error(), "invalidSyntax")
		}
		if strings.TrimSpace(in.UserName) == "" {
			return scimError(c, 400, "userName is required", "invalidValue")
		}
		reqOwner := ""
		if in.Hanzo != nil {
			reqOwner = in.Hanzo.Owner
		}
		owner, err := authz.Scope(ctx, reqOwner)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		if owner == "" {
			return scimError(c, 400, "a SuperAdmin must name the tenant owner (hanzo extension `owner`)", "invalidValue")
		}

		u := schema.User{}
		password := applyToUser(&in, &u)
		u.Owner, u.Name = owner, in.UserName

		created, err := users.New(db).Create(ctx, &users.CreateInput{User: u, Password: password})
		if err != nil {
			return mapErr(c, err)
		}
		return scimJSON(c, 201, toSCIM(created)) // Create already returns a masked user
	}
}

// replaceUser serves PUT /Users/{owner}/{name} — a full replace of the mutable
// attributes. Identity is fixed by the path; the body's own id/owner cannot move
// the row.
func replaceUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, err := scopedTarget(c)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		var in scimUser
		if err := decodeSCIM(c, &in); err != nil {
			return scimError(c, 400, "invalid SCIM body: "+err.Error(), "invalidSyntax")
		}
		u := schema.User{}
		password := applyToUser(&in, &u)
		u.Owner, u.Name = owner, name

		updated, err := users.New(db).Update(ctx, &users.UpdateInput{User: u, Password: password})
		if err != nil {
			return mapErr(c, err)
		}
		return scimJSON(c, 200, toSCIM(updated))
	}
}

// patchUser serves PATCH /Users/{owner}/{name} (RFC 7644 §3.5.2). It reads the
// current row, applies the operations, and writes it back through the canonical
// update path — so a partial change (activate/deactivate, set password, edit a
// field) never blanks the rest of the record.
func patchUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, err := scopedTarget(c)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		cur, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return scimError(c, 500, err.Error(), "")
		}
		if cur == nil {
			return scimError(c, 404, "User "+owner+"/"+name+" not found", "")
		}

		var patch struct {
			Schemas    []string `json:"schemas"`
			Operations []struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value any    `json:"value"`
			} `json:"Operations"`
		}
		if err := decodeSCIM(c, &patch); err != nil {
			return scimError(c, 400, "invalid PatchOp body: "+err.Error(), "invalidSyntax")
		}

		// Start from the current row so unset fields are preserved across the patch.
		next := scimUser{
			UserName:     cur.Name,
			DisplayName:  cur.DisplayName,
			Active:       !cur.IsForbidden && !cur.IsDeleted,
			Name:         &scimName{GivenName: cur.FirstName, FamilyName: cur.LastName},
			Emails:       []scimMultiValued{{Value: cur.Email, Primary: true}},
			PhoneNumbers: []scimMultiValued{{Value: cur.Phone, Primary: true}},
			Hanzo:        &hanzoUserExt{Owner: cur.Owner, IsAdmin: cur.IsAdmin},
		}
		password := ""
		for _, op := range patch.Operations {
			if err := applyPatchOp(&next, &password, strings.ToLower(op.Op), strings.ToLower(op.Path), op.Value); err != nil {
				return scimError(c, 400, err.Error(), "invalidValue")
			}
		}

		u := schema.User{}
		pw := applyToUser(&next, &u)
		if password != "" {
			pw = password
		}
		u.Owner, u.Name = owner, name
		updated, err := users.New(db).Update(ctx, &users.UpdateInput{User: u, Password: pw})
		if err != nil {
			return mapErr(c, err)
		}
		return scimJSON(c, 200, toSCIM(updated))
	}
}

// applyPatchOp applies one RFC 7644 §3.5.2 operation to the working SCIM user.
// It supports the provisioning-practical subset: add/replace/remove on the common
// top-level paths, plus a path-less replace whose value is a partial resource
// (a value map merged in — what Okta/Azure AD send to (de)activate or edit). A
// `password` set is captured separately (write-only). An unknown path is rejected.
func applyPatchOp(u *scimUser, password *string, op, path string, value any) error {
	switch op {
	case "add", "replace":
		if path == "" {
			// Path-less: value is a map of attribute→value to merge.
			m, ok := value.(map[string]any)
			if !ok {
				return errors.New("a path-less patch op requires an object value")
			}
			for k, v := range m {
				if err := applyPatchOp(u, password, "replace", strings.ToLower(k), v); err != nil {
					return err
				}
			}
			return nil
		}
		return setPatchPath(u, password, path, value)
	case "remove":
		return setPatchPath(u, password, path, "")
	default:
		return errors.New("unsupported patch op: " + op)
	}
}

// setPatchPath sets one attribute by its (lowercased) SCIM path.
func setPatchPath(u *scimUser, password *string, path string, value any) error {
	switch path {
	case "active":
		u.Active = truthy(value)
	case "displayname":
		u.DisplayName = str(value)
	case "password":
		*password = str(value)
	case "name.givenname":
		ensureName(u).GivenName = str(value)
	case "name.familyname":
		ensureName(u).FamilyName = str(value)
	case "emails", "emails.value":
		u.Emails = []scimMultiValued{{Value: firstMultiValue(value), Primary: true}}
	case "phonenumbers", "phonenumbers.value":
		u.PhoneNumbers = []scimMultiValued{{Value: firstMultiValue(value), Primary: true}}
	default:
		return errors.New("unsupported patch path: " + path)
	}
	return nil
}

func ensureName(u *scimUser) *scimName {
	if u.Name == nil {
		u.Name = &scimName{}
	}
	return u.Name
}

// firstMultiValue extracts a string from a SCIM value that may be a bare string or
// a multi-valued array (`[{value:"x"}]`).
func firstMultiValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			if m, ok := v[0].(map[string]any); ok {
				return str(m["value"])
			}
		}
	case map[string]any:
		return str(v["value"])
	}
	return ""
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}

// deleteUser serves DELETE /Users/{owner}/{name}.
func deleteUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, err := scopedTarget(c)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		if _, err := users.New(db).Delete(ctx, &users.Ref{Owner: owner, Name: name}); err != nil {
			return mapErr(c, err)
		}
		c.SetHeader("Content-Type", contentTypeSCIM)
		return c.Status(204).JSON(204, struct{}{}) // 204 No Content (RFC 7644 §3.6)
	}
}

// scopedTarget resolves the (owner, name) a path-targeted request addresses,
// re-scoping the path owner through authz.Scope so a non-super can never reach
// another tenant's row by spelling its id — the same pin the query-target reads use.
func scopedTarget(c *zip.Ctx) (owner, name string, err error) {
	pathOwner, pathName := c.Param("owner"), c.Param("name")
	if pathName == "" {
		return "", "", errors.New("a user id (owner/name) is required")
	}
	scoped, err := authz.Scope(c.Context(), pathOwner)
	if err != nil {
		return "", "", err
	}
	if scoped == "" { // SuperAdmin addressing an unspecified owner
		scoped = pathOwner
	}
	return scoped, pathName, nil
}

// pageParams reads SCIM pagination (startIndex 1-based, count), clamped.
func pageParams(c *zip.Ctx) (startIndex, perPage int) {
	startIndex = atoiDefault(c.Query("startIndex"), 1)
	if startIndex < 1 {
		startIndex = 1
	}
	perPage = atoiDefault(c.Query("count"), scimDefaultPerPage)
	if perPage < 0 {
		perPage = 0
	}
	if perPage > scimMaxResults {
		perPage = scimMaxResults
	}
	return startIndex, perPage
}

// parseEqFilter parses the practical SCIM filter subset `attr eq "value"` used for
// provisioning lookups. Returns (field, value, ok); ok=false when there is no
// filter. A malformed filter returns ok=false and the caller may 400.
func parseEqFilter(filter string) (field, value string, ok bool) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", "", false
	}
	parts := strings.SplitN(filter, " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") {
		return "", "", false
	}
	v := strings.TrimSpace(parts[2])
	v = strings.TrimPrefix(v, "\"")
	v = strings.TrimSuffix(v, "\"")
	return strings.ToLower(parts[0]), v, true
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// mapErr converts a canonical users.API (zip.HTTPError) into a SCIM Error with the
// matching status + scimType.
func mapErr(c *zip.Ctx, err error) error {
	var he *zip.HTTPError
	if errors.As(err, &he) {
		scimType := ""
		if he.Status == 409 {
			scimType = "uniqueness"
		}
		return scimError(c, he.Status, he.Msg, scimType)
	}
	return scimError(c, 500, err.Error(), "")
}

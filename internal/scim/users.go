// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package scim

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
	"github.com/hanzoai/iam/internal/users"
)

const (
	scimMaxResults     = 200 // hard cap on a page, whatever count is asked
	scimDefaultPerPage = 100
	entityUsers        = "users" // authz entity name (matches authz.entityOf)
)

// decodeSCIM unmarshals the raw request body into v, independent of Content-Type:
// SCIM clients send `application/scim+json`, which a content-type-dispatching body
// parser may not recognize as JSON. The body IS JSON (RFC 7644 §3.1), parse it so.
func decodeSCIM(c *zip.Ctx, v any) error {
	body := c.Body()
	if len(body) == 0 {
		return errors.New("empty request body")
	}
	return json.Unmarshal(body, v)
}

// scimUser is the SCIM 2.0 core User (RFC 7643 §4.1) plus a Hanzo extension for the
// tenant owner + admin flag. It backs both request and response; the write-only
// `password` is never set on a response. `Active` is a pointer so an omitted field
// is distinguishable from `false` (RFC 7643: active defaults to true).
type scimUser struct {
	Schemas      []string          `json:"schemas"`
	ID           string            `json:"id,omitempty"`
	ExternalID   string            `json:"externalId,omitempty"`
	UserName     string            `json:"userName"`
	Name         *scimName         `json:"name,omitempty"`
	DisplayName  string            `json:"displayName,omitempty"`
	UserType     string            `json:"userType,omitempty"`
	ProfileURL   string            `json:"profileUrl,omitempty"`
	Emails       []scimMultiValued `json:"emails,omitempty"`
	PhoneNumbers []scimMultiValued `json:"phoneNumbers,omitempty"`
	Photos       []scimMultiValued `json:"photos,omitempty"`
	Addresses    []scimAddress     `json:"addresses,omitempty"`
	Active       *bool             `json:"active,omitempty"`
	Password     string            `json:"password,omitempty"`
	Hanzo        *hanzoUserExt     `json:"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User,omitempty"`
	Meta         *scimMeta         `json:"meta,omitempty"`
}

// scimAddress is the SCIM address sub-attribute set this service persists (RFC
// 7643 §4.1.2). streetAddress/postalCode have no column on the identity row, so
// they are not accepted rather than accepted-and-dropped.
type scimAddress struct {
	Locality string `json:"locality,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
	Type     string `json:"type,omitempty"`
	Primary  bool   `json:"primary,omitempty"`
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
	active := !u.IsForbidden && !u.IsDeleted
	s := &scimUser{
		Schemas:     []string{schemaUser, schemaHanzoUserExt},
		ID:          u.Owner + "/" + u.Name,
		ExternalID:  u.ExternalId,
		UserName:    u.Name,
		DisplayName: u.DisplayName,
		UserType:    u.Type,
		ProfileURL:  u.Homepage,
		Active:      &active,
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
	if u.Location != "" || u.Region != "" || u.CountryCode != "" {
		s.Addresses = []scimAddress{{
			Locality: u.Location, Region: u.Region, Country: u.CountryCode,
			Type: "work", Primary: true,
		}}
	}
	return s
}

// primaryAddress returns the primary address entry, or the first. The identity row
// holds ONE address, so a multi-valued request collapses to the primary — the same
// rule primaryValue applies to emails and phones.
func primaryAddress(vs []scimAddress) (scimAddress, bool) {
	if len(vs) == 0 {
		return scimAddress{}, false
	}
	for _, v := range vs {
		if v.Primary {
			return v, true
		}
	}
	return vs[0], true
}

// applyToUser overlays a SCIM User's mapped attributes ONTO u — which is the FULL
// current row on an update (so every unmapped field: MFA enrollment, IsDeleted,
// Type, Groups, Ldap, … is PRESERVED) or a blank record on a create. It never sets
// identity (owner/name); the caller binds those. isAdmin is a privileged field:
// it is applied only when allowAdmin (SuperAdmin) — a non-super can never set or
// raise it (provision-don't-promote), so an omitted-or-present isAdmin from a
// non-super is ignored, leaving u's existing value. Returns the write-only password.
func applyToUser(in *scimUser, u *schema.User, allowAdmin bool) (password string) {
	u.DisplayName = in.DisplayName
	if in.Name != nil {
		u.FirstName, u.LastName = in.Name.GivenName, in.Name.FamilyName
	}
	// externalId is the PROVISIONING CLIENT's own key for this record — the value an
	// IdP correlates its directory entry by. It is not identity (owner/name is) and
	// it is not a credential; carrying it is what makes a repeat sync an update
	// rather than a duplicate create.
	u.ExternalId = in.ExternalID
	u.Homepage = in.ProfileURL
	// userType is deliberately NOT applied. schema.User.Type is the IDENTITY-CLASS
	// discriminator, not a profile label: Type == "service-account" is what
	// serviceaccounts.is() tests (internal/serviceaccounts/serviceaccounts.go:327,
	// gated at :216) and what oidc/provision.go mints a tenant's pk-/sk- API
	// credential as. Honouring a client-supplied userType would let anyone who can
	// provision a user through SCIM mint a row the service-account surface accepts —
	// an identity-class escalation across a boundary IAM otherwise owns. It is
	// declared mutability:readOnly in the /Schemas document (RFC 7643 §7: a readOnly
	// attribute in a write is ignored) and projected on read only.
	u.Email = primaryValue(in.Emails)
	u.Phone = primaryValue(in.PhoneNumbers)
	if v := primaryValue(in.Photos); v != "" {
		u.Avatar = v
	}
	if a, ok := primaryAddress(in.Addresses); ok {
		u.Location, u.Region, u.CountryCode = a.Locality, a.Region, a.Country
	} else {
		u.Location, u.Region, u.CountryCode = "", "", ""
	}
	// active defaults to true when omitted (RFC 7643 §4.1.1); active=false
	// soft-disables (IsForbidden).
	u.IsForbidden = !(in.Active == nil || *in.Active)
	if allowAdmin && in.Hanzo != nil {
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

// listUsers returns the people in your organization to your identity provider,
// in the standard SCIM shape, so an IdP can reconcile its directory against
// ours. Searchable by username or email address, and paged.
//
// Reading the whole list takes an administrator; an ordinary person is refused.
func listUsers(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, err := authz.Scope(ctx, c.Query("owner"))
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		if !authz.Can(ctx, "GET", entityUsers, owner, "") {
			return scimError(c, 403, "listing users requires org-admin", "")
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
				return scimError(c, 400, "unsupported filter attribute: "+field, "invalidFilter")
			}
		}

		total, err := q.Count(ctx)
		if err != nil {
			return scimError(c, 500, "internal error", "")
		}
		startIndex, perPage := pageParams(c)
		rows, err := q.Order("Name").Limit(perPage).Offset(startIndex - 1).GetAll(ctx)
		if err != nil {
			return scimError(c, 500, "internal error", "")
		}
		resources := make([]any, 0, len(rows))
		for _, u := range rows {
			resources = append(resources, toSCIM(u.Mask()))
		}
		return scimList(c, total, startIndex, len(resources), resources)
	}
}

// getUser returns one person in the standard SCIM shape. An administrator may
// read anyone in the organization; everyone else may read only themselves.
func getUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, err := scopedTarget(c)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		if !authz.Can(ctx, "GET", entityUsers, owner, name) {
			return scimError(c, 403, "insufficient privileges", "")
		}
		u, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return scimError(c, 500, "internal error", "")
		}
		if u == nil {
			return scimError(c, 404, "User "+owner+"/"+name+" not found", "")
		}
		return scimJSON(c, 200, toSCIM(u.Mask()))
	}
}

// createUser provisions a person from your identity provider — how a new hire
// gets an account here automatically when they are added over there.
//
// Takes an administrator. Making someone an administrator takes more than that,
// so an IdP integration cannot escalate anyone by setting a flag.
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
		if !authz.Can(ctx, "POST", entityUsers, owner, in.UserName) {
			return scimError(c, 403, "provisioning users requires org-admin", "")
		}

		u := schema.User{}
		password := applyToUser(&in, &u, authz.IsSuper(ctx))
		u.Owner, u.Name = owner, in.UserName

		created, err := users.New(db).Create(ctx, &users.CreateInput{User: u, Password: password})
		if err != nil {
			return mapErr(c, err)
		}
		return scimJSON(c, 201, toSCIM(created))
	}
}

// replaceUser overwrites a person's SCIM attributes with what your identity
// provider sends — how a change made there lands here.
//
// Only the attributes SCIM describes are replaced. Anything the standard does not
// cover — their multi-factor enrolment above all — survives untouched, so a
// routine sync from your IdP can never quietly strip someone's second factor or
// bring a deleted account back.
func replaceUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, err := scopedTarget(c)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		if !authz.Can(ctx, "PUT", entityUsers, owner, name) {
			return scimError(c, 403, "modifying users requires org-admin", "")
		}
		cur, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return scimError(c, 500, "internal error", "")
		}
		if cur == nil {
			return scimError(c, 404, "User "+owner+"/"+name+" not found", "")
		}
		var in scimUser
		if err := decodeSCIM(c, &in); err != nil {
			return scimError(c, 400, "invalid SCIM body: "+err.Error(), "invalidSyntax")
		}
		password := applyToUser(&in, cur, authz.IsSuper(ctx)) // overlay onto the FULL row
		cur.Owner, cur.Name = owner, name

		updated, err := users.New(db).Update(ctx, &users.UpdateInput{User: *cur, Password: password})
		if err != nil {
			return mapErr(c, err)
		}
		return scimJSON(c, 200, toSCIM(updated))
	}
}

// patchUser applies a partial change from your identity provider — one attribute
// moved, not the whole record resent.
//
// The change is applied onto the person as they currently are, so everything you
// did not mention keeps its value, including the parts SCIM does not describe.
func patchUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, err := scopedTarget(c)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		if !authz.Can(ctx, "PATCH", entityUsers, owner, name) {
			return scimError(c, 403, "modifying users requires org-admin", "")
		}
		cur, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return scimError(c, 500, "internal error", "")
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

		// Start the working projection from the current row so unset attributes are
		// preserved across the patch.
		curActive := !cur.IsForbidden && !cur.IsDeleted
		next := scimUser{
			UserName:     cur.Name,
			ExternalID:   cur.ExternalId,
			DisplayName:  cur.DisplayName,
			ProfileURL:   cur.Homepage,
			Active:       &curActive,
			Name:         &scimName{GivenName: cur.FirstName, FamilyName: cur.LastName},
			Emails:       []scimMultiValued{{Value: cur.Email, Primary: true}},
			PhoneNumbers: []scimMultiValued{{Value: cur.Phone, Primary: true}},
			Addresses: []scimAddress{{
				Locality: cur.Location, Region: cur.Region, Country: cur.CountryCode, Primary: true,
			}},
			Hanzo: &hanzoUserExt{Owner: cur.Owner, IsAdmin: cur.IsAdmin},
		}
		password := ""
		for _, op := range patch.Operations {
			if err := applyPatchOp(&next, &password, strings.ToLower(op.Op), strings.ToLower(op.Path), op.Value); err != nil {
				return scimError(c, 400, err.Error(), "invalidValue")
			}
		}

		// Overlay the patched projection onto the FULL current row (preserving MFA,
		// IsDeleted, Type, Groups, …), then write.
		if pw := applyToUser(&next, cur, authz.IsSuper(ctx)); pw != "" {
			password = pw
		}
		cur.Owner, cur.Name = owner, name
		updated, err := users.New(db).Update(ctx, &users.UpdateInput{User: *cur, Password: password})
		if err != nil {
			return mapErr(c, err)
		}
		return scimJSON(c, 200, toSCIM(updated))
	}
}

// deleteUser deprovisions a person — how removing someone in your identity
// provider removes their access here. Their sessions stop working immediately.
// Takes an administrator.
func deleteUser(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, err := scopedTarget(c)
		if err != nil {
			return scimError(c, 403, err.Error(), "")
		}
		if !authz.Can(ctx, "DELETE", entityUsers, owner, name) {
			return scimError(c, 403, "deleting users requires org-admin", "")
		}
		if _, err := users.New(db).Delete(ctx, &users.Ref{Owner: owner, Name: name}); err != nil {
			return mapErr(c, err)
		}
		c.SetHeader("Content-Type", contentTypeSCIM)
		return c.Status(204).JSON(204, struct{}{}) // 204 No Content (RFC 7644 §3.6)
	}
}

// applyPatchOp applies one RFC 7644 §3.5.2 operation to the working SCIM user.
// Supports the provisioning-practical subset: add/replace/remove on the common
// top-level paths, plus a path-less replace whose value is a partial resource. A
// `password` set is captured separately (write-only). An unknown path is rejected;
// isAdmin is NOT a patchable path (provision-don't-promote — set only via a
// SuperAdmin create/PUT with the Hanzo extension).
func applyPatchOp(u *scimUser, password *string, op, path string, value any) error {
	switch op {
	case "add", "replace":
		if path == "" {
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
		b := truthy(value)
		u.Active = &b
	case "displayname":
		u.DisplayName = str(value)
	case "externalid":
		u.ExternalID = str(value)
	case "profileurl":
		u.ProfileURL = str(value)
	case "addresses", "addresses.locality", "addresses.region", "addresses.country":
		patchAddress(u, path, value)
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

// patchAddress applies a patch to the single address the identity row holds —
// either the whole `addresses` value or one sub-attribute path.
func patchAddress(u *scimUser, path string, value any) {
	cur, _ := primaryAddress(u.Addresses)
	cur.Primary = true
	switch path {
	case "addresses":
		var m map[string]any
		switch v := value.(type) {
		case map[string]any:
			m = v
		case []any:
			if len(v) > 0 {
				m, _ = v[0].(map[string]any)
			}
		}
		cur.Locality, cur.Region, cur.Country = str(m["locality"]), str(m["region"]), str(m["country"])
	case "addresses.locality":
		cur.Locality = str(value)
	case "addresses.region":
		cur.Region = str(value)
	case "addresses.country":
		cur.Country = str(value)
	}
	u.Addresses = []scimAddress{cur}
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

// pageParams reads SCIM pagination (startIndex 1-based, count), clamped. A
// non-positive count is the DEFAULT page size, never unbounded — orm's Limit(0)
// emits no LIMIT clause, so an unclamped 0 would dump the whole set.
func pageParams(c *zip.Ctx) (startIndex, perPage int) {
	startIndex = atoiDefault(c.Query("startIndex"), 1)
	if startIndex < 1 {
		startIndex = 1
	}
	perPage = atoiDefault(c.Query("count"), scimDefaultPerPage)
	if perPage <= 0 {
		perPage = scimDefaultPerPage
	}
	if perPage > scimMaxResults {
		perPage = scimMaxResults
	}
	return startIndex, perPage
}

// parseEqFilter parses the practical SCIM filter subset `attr eq "value"`.
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
// matching status + scimType. A non-HTTPError is a generic 500 (no internal detail).
func mapErr(c *zip.Ctx, err error) error {
	var he *zip.HTTPError
	if errors.As(err, &he) {
		scimType := ""
		if he.Status == 409 {
			scimType = "uniqueness"
		}
		return scimError(c, he.Status, he.Msg, scimType)
	}
	return scimError(c, 500, "internal error", "")
}

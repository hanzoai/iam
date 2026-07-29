// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package scim_test

// The provisioning contract a real IdP (Okta, Entra) depends on, driven through
// the REAL registered router. Three things are pinned here:
//
//   - externalId round-trips. It is the IdP's OWN key for the record; an IdP that
//     cannot read back what it wrote re-creates the user on every sync.
//   - the profile attributes an IdP actually sends (userType, profileUrl,
//     addresses) reach the stored row instead of being silently discarded.
//   - discovery (/Schemas, /ResourceTypes) answers, and answers the schema this
//     service ACTUALLY implements.
//
// And the security pin: the STANDARD enterprise extension's free-text
// `organization` must never choose the tenant. There is ONE way to name a tenant
// on this surface — the Hanzo extension's `owner`, re-scoped through authz.Scope.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/store"
)

const enterpriseURN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

// scimFullResp is the response projection these tests assert on — the attributes
// an IdP reads back after a write.
type scimFullResp struct {
	ID         string `json:"id"`
	UserName   string `json:"userName"`
	ExternalID string `json:"externalId"`
	UserType   string `json:"userType"`
	ProfileURL string `json:"profileUrl"`
	Addresses  []struct {
		Locality string `json:"locality"`
		Region   string `json:"region"`
		Country  string `json:"country"`
	} `json:"addresses"`
}

// TestSCIM_externalId_roundTrips: the IdP's correlation key survives a create and
// is returned on read. Dropping it makes every sync look like a new user.
func TestSCIM_externalId_roundTrips(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")

	create := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"dana","externalId":"okta-00u1a2b3c4",
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo"}}`
	status, body := h.do(t, "POST", scimUsers, super, create)
	if status != 201 {
		t.Fatalf("create status = %d; body=%s", status, body)
	}
	var got scimFullResp
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("create body: %v", err)
	}
	if got.ExternalID != "okta-00u1a2b3c4" {
		t.Fatalf("create externalId = %q, want okta-00u1a2b3c4 (body=%s)", got.ExternalID, body)
	}

	// It reached the stored row, not just the echo.
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "dana")
	if u == nil || u.ExternalId != "okta-00u1a2b3c4" {
		t.Fatalf("stored ExternalId = %q, want okta-00u1a2b3c4", u.ExternalId)
	}

	// And it is readable back.
	status, body = h.do(t, "GET", scimUsers+"/hanzo/dana", super, "")
	if status != 200 {
		t.Fatalf("get status = %d", status)
	}
	got = scimFullResp{}
	_ = json.Unmarshal([]byte(body), &got)
	if got.ExternalID != "okta-00u1a2b3c4" {
		t.Fatalf("get externalId = %q, want okta-00u1a2b3c4 (body=%s)", got.ExternalID, body)
	}
}

// TestSCIM_profileAttributes_roundTrip: profileUrl and addresses are mapped, not
// discarded. (userType is NOT writable — see TestRed_userType_cannotMintServiceAccount.)
func TestSCIM_profileAttributes_roundTrip(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")

	create := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"erin","profileUrl":"https://hanzo.ai/u/erin",
		"addresses":[{"locality":"Los Angeles","region":"CA","country":"US"}],
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo"}}`
	if status, body := h.do(t, "POST", scimUsers, super, create); status != 201 {
		t.Fatalf("create status = %d; body=%s", status, body)
	}

	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "erin")
	if u == nil {
		t.Fatal("user not created")
	}
	if u.Homepage != "https://hanzo.ai/u/erin" {
		t.Errorf("stored Homepage = %q, want the profileUrl", u.Homepage)
	}
	if u.Location != "Los Angeles" || u.Region != "CA" || u.CountryCode != "US" {
		t.Errorf("stored address = %q/%q/%q, want Los Angeles/CA/US", u.Location, u.Region, u.CountryCode)
	}

	status, body := h.do(t, "GET", scimUsers+"/hanzo/erin", super, "")
	if status != 200 {
		t.Fatalf("get status = %d", status)
	}
	var got scimFullResp
	_ = json.Unmarshal([]byte(body), &got)
	if got.ProfileURL != "https://hanzo.ai/u/erin" {
		t.Errorf("read back profileUrl = %q (body=%s)", got.ProfileURL, body)
	}
	if len(got.Addresses) != 1 || got.Addresses[0].Locality != "Los Angeles" {
		t.Errorf("read back addresses = %+v (body=%s)", got.Addresses, body)
	}
}

// TestRed_userType_cannotMintServiceAccount is the identity-class pin.
//
// schema.User.Type is NOT a profile label — Type == "service-account" is the
// discriminator internal/serviceaccounts.is() tests before it will hand out or
// rotate a pk-/sk- API credential, and the class oidc/provision.go mints a
// tenant's default credential as. A SCIM `userType` is client-supplied, so
// honouring it on write would let anyone who can provision a user (an org-admin,
// or the IdP integration that holds the provisioning token) mint a row the
// service-account surface accepts — reaching an identity class IAM otherwise
// hands out only through its own gated route.
//
// RFC 7643 §7 mutability:readOnly — a readOnly attribute in a write is IGNORED,
// not an error. So the write is accepted and the class is unchanged.
func TestRed_userType_cannotMintServiceAccount(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root") // the STRONGEST caller — still cannot do this

	create := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"sneaky","userType":"service-account",
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo"}}`
	if status, body := h.do(t, "POST", scimUsers, super, create); status != 201 {
		t.Fatalf("create status = %d; body=%s", status, body)
	}
	ctx := context.Background()
	u, _ := store.GetUserByName(ctx, h.db, "hanzo", "sneaky")
	if u == nil {
		t.Fatal("user not created")
	}
	if u.Type == "service-account" {
		t.Fatal("IDENTITY-CLASS ESCALATION: SCIM create minted a service account via userType")
	}

	// Nor by PUT onto an existing human.
	replace := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"sneaky","userType":"service-account"}`
	if status, body := h.do(t, "PUT", scimUsers+"/hanzo/sneaky", super, replace); status != 200 {
		t.Fatalf("put status = %d; body=%s", status, body)
	}
	u, _ = store.GetUserByName(ctx, h.db, "hanzo", "sneaky")
	if u.Type == "service-account" {
		t.Fatal("IDENTITY-CLASS ESCALATION: SCIM PUT promoted a human to a service account")
	}

	// Nor by PATCH — an unknown/readOnly path is refused outright there.
	patch := `{"schemas":["urn:ietf:params:scim:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"userType","value":"service-account"}]}`
	h.do(t, "PATCH", scimUsers+"/hanzo/sneaky", super, patch)
	u, _ = store.GetUserByName(ctx, h.db, "hanzo", "sneaky")
	if u.Type == "service-account" {
		t.Fatal("IDENTITY-CLASS ESCALATION: SCIM PATCH promoted a human to a service account")
	}
}

// TestSCIM_discovery_schemasAndResourceTypes: an IdP discovers the surface before
// provisioning against it (RFC 7644 §4).
func TestSCIM_discovery_schemasAndResourceTypes(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "hanzo/boss")

	for _, tc := range []struct{ path, want string }{
		{"/Schemas", "urn:ietf:params:scim:schemas:core:2.0:User"},
		{"/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "userName"},
		{"/ResourceTypes", "/Users"},
		{"/ResourceTypes/User", "urn:ietf:params:scim:schemas:core:2.0:User"},
	} {
		status, body := h.do(t, "GET", "/v1/iam/scim/v2"+tc.path, tok, "")
		if status != 200 {
			t.Errorf("GET %s status = %d, want 200 (body=%s)", tc.path, status, body)
			continue
		}
		if !strings.Contains(body, tc.want) {
			t.Errorf("GET %s body missing %q:\n%s", tc.path, tc.want, body)
		}
	}

	// An unknown schema id is a SCIM 404, not a 200 with an empty body.
	if status, _ := h.do(t, "GET", "/v1/iam/scim/v2/Schemas/urn:made:up", tok, ""); status != 404 {
		t.Errorf("unknown schema id status = %d, want 404", status)
	}
}

// TestRed_enterpriseExtension_cannotNameTheTenant is the tenant-isolation pin.
// The standard enterprise extension's `organization` is FREE TEXT describing where
// a person works (RFC 7643 §4.3) — it is not a tenant key, and an IdP controls it.
// Honouring it would hand any client that can provision into its own org a way to
// write into another one. The tenant comes from authz.Scope and nowhere else.
func TestRed_enterpriseExtension_cannotNameTheTenant(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss") // org-admin of hanzo, NOT super

	create := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","` + enterpriseURN + `"],
		"userName":"mallory","` + enterpriseURN + `":{"organization":"orgb"}}`
	status, body := h.do(t, "POST", scimUsers, boss, create)
	if status != 201 {
		t.Fatalf("create status = %d; body=%s", status, body)
	}

	ctx := context.Background()
	if u, _ := store.GetUserByName(ctx, h.db, "orgb", "mallory"); u != nil {
		t.Fatal("TENANT BREACH: enterprise-extension `organization` placed the user in orgb")
	}
	if u, _ := store.GetUserByName(ctx, h.db, "hanzo", "mallory"); u == nil {
		t.Fatal("user did not land in the caller's own org")
	}
}

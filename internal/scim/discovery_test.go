// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package scim_test

// SCIM discovery (RFC 7644 §4) is a PUBLISHED document: an IdP connector reads
// /ServiceProviderConfig, /Schemas and /ResourceTypes once, configures itself
// from what it finds, and never asks again. So the wire is the contract, and this
// file pins it — the exact bytes of the two documents this package builds by
// hand (the capability document, and the Error a client gets for an item we do
// not publish), the identity of the ones it publishes from tables, and the fact
// that all five are TYPED ops rather than five addresses only a hand-written
// integration could find.

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/testhttp"
)

const (
	discovery = "/v1/iam/scim/v2"
	userURN   = "urn:ietf:params:scim:schemas:core:2.0:User"
	hanzoURN  = "urn:ietf:params:scim:schemas:extension:hanzo:2.0:User"

	// The capability document, byte for byte. It is short, it never varies, and
	// every field in it is a promise an IdP acts on — "do not attempt bulk", "you
	// may send a filter, up to 200 results". A diff here is an API change.
	wantConfig = `{"authenticationSchemes":[{"description":"Authentication via an OAuth 2.0 bearer access token (HIP-0111).",` +
		`"name":"OAuth Bearer Token","primary":true,"type":"oauthbearertoken"}],` +
		`"bulk":{"maxOperations":0,"maxPayloadSize":0,"supported":false},"changePassword":{"supported":true},` +
		`"documentationUri":"https://github.com/hanzoai/hips/blob/main/HIPs/hip-0111-iam-authentication-standard.md",` +
		`"etag":{"supported":false},"filter":{"maxResults":200,"supported":true},"patch":{"supported":true},` +
		`"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],"sort":{"supported":false}}`
)

// TestDiscovery_answersEveryReader: discovery belongs to no tenant, so an
// ordinary member reads it exactly as an admin does. This is the sharp case for
// the op-invoke authorizer — these inputs carry no owner and no name, so the
// decoded target is empty and the read is admitted; an input that named a target
// would 403 here for the non-admin and pass for everyone else.
func TestDiscovery_answersEveryReader(t *testing.T) {
	h := newHarness(t)
	for _, who := range []string{"admin/root", "hanzo/boss", "hanzo/alice"} {
		for _, path := range []string{
			"/ServiceProviderConfig", "/Schemas", "/ResourceTypes",
			"/Schemas/" + userURN, "/ResourceTypes/User",
		} {
			if status, body := h.do(t, "GET", discovery+path, h.token(t, who), ""); status != 200 {
				t.Errorf("GET %s as %s = %d, want 200; body=%s", path, who, status, body)
			}
		}
	}
}

// TestDiscovery_serviceProviderConfig pins the capability document byte for byte.
func TestDiscovery_serviceProviderConfig(t *testing.T) {
	h := newHarness(t)
	status, body := h.do(t, "GET", discovery+"/ServiceProviderConfig", h.token(t, "hanzo/boss"), "")
	if status != 200 {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	if body != wantConfig {
		t.Errorf("ServiceProviderConfig changed on the wire.\n got: %s\nwant: %s", body, wantConfig)
	}
}

// TestDiscovery_itemAnswersTheSegmentItWasGiven is the path-binding pin. Neither
// input field is called Name (the authorizer reads that name off the decoded
// input), so the segment binds by its json tag — and a binding that silently did
// not happen would answer the wrong document, or say "Schema  not found".
func TestDiscovery_itemAnswersTheSegmentItWasGiven(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "hanzo/boss")

	for _, want := range []string{userURN, hanzoURN} {
		status, body := h.do(t, "GET", discovery+"/Schemas/"+want, tok, "")
		if status != 200 {
			t.Fatalf("GET /Schemas/%s = %d; body=%s", want, status, body)
		}
		var got struct {
			ID   string `json:"id"`
			Meta struct {
				Location string `json:"location"`
			} `json:"meta"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("not a Schema document: %v", err)
		}
		if got.ID != want {
			t.Errorf("GET /Schemas/%s answered id %q", want, got.ID)
		}
		if suffix := "/Schemas/" + want; !strings.HasSuffix(got.Meta.Location, suffix) {
			t.Errorf("meta.location = %q, want it to end %q", got.Meta.Location, suffix)
		}
	}

	status, body := h.do(t, "GET", discovery+"/ResourceTypes/User", tok, "")
	if status != 200 {
		t.Fatalf("GET /ResourceTypes/User = %d; body=%s", status, body)
	}
	var kind struct {
		ID       string `json:"id"`
		Endpoint string `json:"endpoint"`
		Schema   string `json:"schema"`
	}
	if err := json.Unmarshal([]byte(body), &kind); err != nil {
		t.Fatalf("not a ResourceType document: %v", err)
	}
	if kind.ID != "User" || kind.Endpoint != "/Users" || kind.Schema != userURN {
		t.Errorf("ResourceType User = %+v, want id User / endpoint /Users / the User schema", kind)
	}
}

// TestDiscovery_unpublishedItemIsASCIMError pins the refusal. RFC 7644 §3.12 has
// its own document, and a client that parses it must not be handed the
// framework's {status,code,error} envelope instead — which is what returning a Go
// error from these ops would send.
func TestDiscovery_unpublishedItemIsASCIMError(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "hanzo/boss")
	for _, tc := range []struct{ path, want string }{
		{"/Schemas/urn:made:up",
			`{"detail":"Schema urn:made:up not found","schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404"}`},
		{"/ResourceTypes/Nope",
			`{"detail":"ResourceType Nope not found","schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404"}`},
	} {
		status, body := h.do(t, "GET", discovery+tc.path, tok, "")
		if status != 404 {
			t.Errorf("GET %s = %d, want 404; body=%s", tc.path, status, body)
		}
		if body != tc.want {
			t.Errorf("GET %s body\n got: %s\nwant: %s", tc.path, body, tc.want)
		}
	}
}

// TestDiscovery_listsEveryPublishedItem: the list and the item endpoints read one
// table, so the list carries every document the item route will serve, and the
// envelope says so — a one-page ListResponse whose counts agree with itself.
func TestDiscovery_listsEveryPublishedItem(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "hanzo/boss")
	for _, tc := range []struct {
		path  string
		count int
	}{{"/Schemas", 2}, {"/ResourceTypes", 1}} {
		status, body := h.do(t, "GET", discovery+tc.path, tok, "")
		if status != 200 {
			t.Fatalf("GET %s = %d; body=%s", tc.path, status, body)
		}
		var got struct {
			Schemas      []string          `json:"schemas"`
			TotalResults int               `json:"totalResults"`
			StartIndex   int               `json:"startIndex"`
			ItemsPerPage int               `json:"itemsPerPage"`
			Resources    []json.RawMessage `json:"Resources"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("GET %s is not a ListResponse: %v", tc.path, err)
		}
		if len(got.Schemas) != 1 || got.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
			t.Errorf("GET %s schemas = %v", tc.path, got.Schemas)
		}
		if got.TotalResults != tc.count || got.ItemsPerPage != tc.count ||
			got.StartIndex != 1 || len(got.Resources) != tc.count {
			t.Errorf("GET %s envelope = total %d, start %d, perPage %d, %d resources; want %d/1/%d/%d",
				tc.path, got.TotalResults, got.StartIndex, got.ItemsPerPage, len(got.Resources),
				tc.count, tc.count, tc.count)
		}
	}
}

// contentType is the Content-Type of a GET, read off the live router.
func (h *harness) contentType(t *testing.T, path, bearer string) string {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.Header.Get("Content-Type")
}

// TestDiscovery_contentTypeIsTheSurfaces pins the response Content-Type, which
// nothing pinned before and which is easy to get wrong from the source alone.
//
// Every SCIM response in this package is written by a helper that first calls
// SetHeader("Content-Type", "application/scim+json"). None of it reaches the
// wire: fiber's Res.JSON takes an OPTIONAL content type and, given none,
// unconditionally overwrites the header with application/json; charset=utf-8
// (fiber/v3@v3.2.1 res.go). Those SetHeader calls have therefore always been
// dead, and the whole surface — the discovery documents here and the /Users CRUD
// that is still raw — answers application/json.
//
// The raw /Users case is in the table as the CONTROL: it is untouched code, so
// the two halves agreeing is what proves the content type is a property of how
// the body is written and not of the typed conversion. RFC 7644 §3.1 asks for
// application/scim+json, so this is a real deviation — but it is the surface's,
// not these five routes', and fixing it here alone would split the surface in
// two. Change both halves together, or neither.
func TestDiscovery_contentTypeIsTheSurfaces(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "hanzo/boss")
	const want = "application/json; charset=utf-8"
	for _, path := range []string{
		discovery + "/ServiceProviderConfig",
		discovery + "/Schemas",
		discovery + "/Schemas/" + userURN,
		discovery + "/Schemas/urn:made:up", // the 404 half
		discovery + "/ResourceTypes",
		discovery + "/ResourceTypes/User",
		discovery + "/ResourceTypes/Nope", // the 404 half
		discovery + "/Users?owner=hanzo",  // control: still a raw handler
	} {
		if got := h.contentType(t, path, tok); got != want {
			t.Errorf("GET %s Content-Type = %q, want %q — the SCIM surface answers one type, "+
				"and a route that differs has split it", path, got, want)
		}
	}
}

// TestDiscovery_isInTheDocument is the point of the conversion. A raw handler
// registers a route and nothing else — it is in no spec, no MCP tool list and no
// generated client. An op is in all of them, under exactly the statuses it
// declares, so a client generated from this document knows a 404 is possible
// before it ships.
func TestDiscovery_isInTheDocument(t *testing.T) {
	h := newHarness(t)
	paths, _ := h.app.OpenAPISpec()["paths"].(map[string]map[string]any)
	if paths == nil {
		t.Fatal("no paths in the OpenAPI document")
	}
	for _, tc := range []struct {
		path     string
		statuses []string
	}{
		{discovery + "/ServiceProviderConfig", []string{"200"}},
		{discovery + "/Schemas", []string{"200"}},
		{discovery + "/Schemas/{id}", []string{"200", "404"}},
		{discovery + "/ResourceTypes", []string{"200"}},
		{discovery + "/ResourceTypes/{name}", []string{"200", "404"}},
	} {
		item, ok := paths[tc.path]
		if !ok {
			t.Errorf("%s is not in the OpenAPI document — it is still a raw handler", tc.path)
			continue
		}
		get, ok := item["get"].(map[string]any)
		if !ok {
			t.Errorf("%s has no GET operation", tc.path)
			continue
		}
		responses, _ := get["responses"].(map[string]any)
		if len(responses) != len(tc.statuses) {
			t.Errorf("%s declares %d responses, want %v", tc.path, len(responses), tc.statuses)
		}
		for _, code := range tc.statuses {
			if _, ok := responses[code]; !ok {
				t.Errorf("%s does not declare a %s response", tc.path, code)
			}
		}
	}
}

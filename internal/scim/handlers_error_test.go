// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package scim_test

// The error branches of the /Users handlers, driven through the REAL router: the
// RFC 7644 §3.12 Errors a SCIM client must be able to parse — a malformed body, a
// missing target, an unsupported filter or PatchOp, and the uniqueness conflict a
// repeat provision must surface as 409 (so an IdP retries instead of duplicating).
// Also the pagination clamps: a client cannot widen a page past the server cap or
// walk off the front of the set.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSCIM_create_errorBranches(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	boss := h.token(t, "hanzo/boss")

	for _, tc := range []struct {
		name       string
		token      string
		body       string
		wantStatus int
		wantType   string // scimType substring the Error must carry ("" = don't check)
	}{
		{
			name: "empty body", token: super, body: "",
			wantStatus: 400, wantType: "invalidSyntax",
		},
		{
			name: "malformed JSON", token: super, body: "{not json",
			wantStatus: 400, wantType: "invalidSyntax",
		},
		{
			name: "blank userName", token: super,
			body:       `{"userName":"   ","urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo"}}`,
			wantStatus: 400, wantType: "invalidValue",
		},
		{
			name: "super names no tenant owner", token: super,
			body:       `{"userName":"nobody"}`,
			wantStatus: 400, wantType: "invalidValue",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := h.do(t, "POST", scimUsers, tc.token, tc.body)
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", status, tc.wantStatus, body)
			}
			if tc.wantType != "" && !strings.Contains(body, tc.wantType) {
				t.Errorf("Error body missing scimType %q:\n%s", tc.wantType, body)
			}
		})
	}

	// A repeat provision of the same id is a uniqueness conflict (mapErr → 409),
	// not a 500 and not a silent second row.
	create := `{"userName":"carol","urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo"}}`
	if status, body := h.do(t, "POST", scimUsers, boss, create); status != 201 {
		t.Fatalf("first create status = %d; body=%s", status, body)
	}
	status, body := h.do(t, "POST", scimUsers, boss, create)
	if status != 409 {
		t.Fatalf("duplicate create status = %d, want 409; body=%s", status, body)
	}
	if !strings.Contains(body, "uniqueness") {
		t.Errorf("409 body missing scimType uniqueness:\n%s", body)
	}
}

func TestSCIM_replace_errorBranches(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")

	// A target that does not exist is a 404 before any body is applied.
	if status, body := h.do(t, "PUT", scimUsers+"/hanzo/ghost", super,
		`{"userName":"ghost"}`); status != 404 {
		t.Fatalf("PUT missing user status = %d, want 404; body=%s", status, body)
	}

	// A malformed body on an existing target is a 400.
	if status, body := h.do(t, "PUT", scimUsers+"/hanzo/alice", super, "{bad"); status != 400 {
		t.Fatalf("PUT malformed body status = %d, want 400; body=%s", status, body)
	}
}

// TestSCIM_delete_missingIsNotFound: deprovisioning a user who is already gone
// answers a SCIM 404 (mapErr on the canonical users.API not-found), never a 500 —
// an IdP that retries a deprovision must get a clean, parseable answer.
func TestSCIM_delete_missingIsNotFound(t *testing.T) {
	h := newHarness(t)
	status, body := h.do(t, "DELETE", scimUsers+"/hanzo/ghost", h.token(t, "admin/root"), "")
	if status != 404 {
		t.Fatalf("delete missing user status = %d, want 404; body=%s", status, body)
	}
	if !strings.Contains(body, "urn:ietf:params:scim:api:messages:2.0:Error") {
		t.Errorf("delete-missing did not return a SCIM Error:\n%s", body)
	}
}

func TestSCIM_patch_errorBranches(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	target := scimUsers + "/hanzo/alice"

	for _, tc := range []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"missing target", "", 404}, // path is /hanzo/ghost below
		{"malformed body", "{bad", 400},
		{"unsupported op", `{"Operations":[{"op":"frobnicate","path":"active","value":true}]}`, 400},
		{"unsupported path", `{"Operations":[{"op":"replace","path":"nope","value":"x"}]}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := target
			if tc.name == "missing target" {
				path = scimUsers + "/hanzo/ghost"
				// A PatchOp body reaches the 404 only after the target load; send a
				// well-formed op so the 404 is the target's, not the body's.
				tc.body = `{"Operations":[{"op":"replace","path":"active","value":false}]}`
			}
			status, body := h.do(t, "PATCH", path, super, tc.body)
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", status, tc.wantStatus, body)
			}
		})
	}
}

// TestSCIM_patch_appliesEveryPath drives a single PATCH carrying one op per
// supported path, then reads the row back — the handler's projection + applyToUser
// overlay, not just the pure helper. A path-less object op fans its members out.
func TestSCIM_patch_appliesEveryPath(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")

	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"displayName","value":"Alice A"},
		{"op":"replace","path":"name.givenName","value":"Alice"},
		{"op":"replace","path":"name.familyName","value":"Anderson"},
		{"op":"replace","path":"profileUrl","value":"https://hanzo.ai/u/alice"},
		{"op":"replace","path":"emails","value":[{"value":"alice@hanzo.ai"}]},
		{"op":"replace","path":"phoneNumbers","value":"+15551234"},
		{"op":"replace","path":"addresses.locality","value":"Austin"},
		{"op":"replace","path":"addresses.region","value":"TX"},
		{"op":"add","value":{"externalId":"okta-alice"}}
	]}`
	status, body := h.do(t, "PATCH", scimUsers+"/hanzo/alice", super, patch)
	if status != 200 {
		t.Fatalf("patch status = %d; body=%s", status, body)
	}

	var got struct {
		DisplayName string `json:"displayName"`
		ExternalID  string `json:"externalId"`
		ProfileURL  string `json:"profileUrl"`
		Name        struct {
			GivenName  string `json:"givenName"`
			FamilyName string `json:"familyName"`
		} `json:"name"`
		Addresses []struct {
			Locality string `json:"locality"`
			Region   string `json:"region"`
		} `json:"addresses"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("patch response: %v", err)
	}
	if got.DisplayName != "Alice A" || got.ExternalID != "okta-alice" ||
		got.ProfileURL != "https://hanzo.ai/u/alice" ||
		got.Name.GivenName != "Alice" || got.Name.FamilyName != "Anderson" {
		t.Errorf("patched projection wrong: %+v", got)
	}
	if len(got.Addresses) != 1 || got.Addresses[0].Locality != "Austin" || got.Addresses[0].Region != "TX" {
		t.Errorf("patched address wrong: %+v", got.Addresses)
	}
}

func TestSCIM_list_filterAndPaging(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	boss := h.token(t, "hanzo/boss")

	// An unsupported filter attribute is a 400 invalidFilter, not a silent full list.
	status, body := h.do(t, "GET", scimUsers+`?owner=hanzo&filter=nickName+eq+%22x%22`, boss, "")
	if status != 400 || !strings.Contains(body, "invalidFilter") {
		t.Fatalf("unsupported filter = %d (%s), want 400 invalidFilter", status, body)
	}

	// Filtering by email normalizes the query, so a differently-cased spelling still
	// finds the one account — the fix that stops an IdP provisioning a duplicate.
	create := `{"userName":"carol","emails":[{"value":"carol@hanzo.ai","primary":true}],
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo"}}`
	if s, b := h.do(t, "POST", scimUsers, super, create); s != 201 {
		t.Fatalf("seed carol status = %d; %s", s, b)
	}
	status, body = h.do(t, "GET", scimUsers+`?owner=hanzo&filter=emails+eq+%22CAROL@HANZO.AI%22`, boss, "")
	if status != 200 {
		t.Fatalf("email filter status = %d; body=%s", status, body)
	}
	var lr listResp
	_ = json.Unmarshal([]byte(body), &lr)
	if lr.TotalResults != 1 {
		t.Fatalf("email filter total = %d, want 1 (case-insensitive match)", lr.TotalResults)
	}

	// Pagination is clamped: startIndex below 1 becomes 1, a count past the cap is
	// bounded, and a non-numeric count falls back to the default — all answer 200.
	for _, q := range []string{"?owner=hanzo&startIndex=0&count=500", "?owner=hanzo&count=notanumber"} {
		if s, b := h.do(t, "GET", scimUsers+q, boss, ""); s != 200 {
			t.Fatalf("GET %s status = %d; body=%s", q, s, b)
		}
	}
}

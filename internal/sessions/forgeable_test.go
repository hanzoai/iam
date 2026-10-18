// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package sessions

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// The one rule for a write the cookie authorizes: the issuer's own page or the
// person, and a JSON body when there is a body. With no Fetch Metadata the page is
// read off Origin against the host the request was sent to.
func TestForgeable(t *testing.T) {
	const host = "hanzo.ai"
	for _, tc := range []struct {
		method, site, origin, contentType string
		forgeable                         bool
	}{
		{http.MethodPost, "same-origin", "", "application/json", false},
		{http.MethodPut, "same-origin", "", "application/json; charset=utf-8", false},
		{http.MethodPost, "none", "", "application/json", false},
		{http.MethodGet, "same-origin", "", "", false},
		{http.MethodPost, "same-site", "", "application/json", true},
		{http.MethodPost, "cross-site", "", "application/json", true},
		{http.MethodGet, "same-site", "", "", true},
		{http.MethodPost, "same-origin", "", "application/x-www-form-urlencoded", true},
		{http.MethodPost, "same-origin", "", "multipart/form-data; boundary=b", true},
		{http.MethodPost, "same-origin", "", "text/plain", true},
		{http.MethodPost, "same-origin", "", "", true},
		{http.MethodPost, "same-origin", "", "application/jsonp", true},
		// Fetch Metadata is believed over Origin.
		{http.MethodPost, "same-site", "https://hanzo.ai", "application/json", true},
		// No Fetch Metadata: an old browser, or a proxy that strips it.
		{http.MethodPost, "", "https://hanzo.ai", "application/json", false},
		{http.MethodPost, "", "https://HANZO.AI", "application/json", false},
		{http.MethodPost, "", "https://hanzo.ai", "application/x-www-form-urlencoded", true},
		{http.MethodPost, "", "https://chat.hanzo.ai", "application/json", true},
		{http.MethodPost, "", "http://hanzo.ai", "application/json", true},
		{http.MethodPost, "", "https://hanzo.ai.evil.example", "application/json", true},
		{http.MethodPost, "", "null", "application/json", true},
		{http.MethodGet, "", "https://chat.hanzo.ai", "", true},
		// Neither: no page sent it.
		{http.MethodPost, "", "", "application/json", false},
		{http.MethodGet, "", "", "", false},
		{http.MethodPost, "", "", "application/x-www-form-urlencoded", true},
	} {
		r := Request{Method: tc.method, Site: tc.site, Origin: tc.origin, Host: host, Type: tc.contentType}
		if got := Forgeable(r); got != tc.forgeable {
			t.Errorf("Forgeable(%+v) = %v, want %v", r, got, tc.forgeable)
		}
	}
}

// A sign-out is refused only when the browser says another page sent it and it is
// not a top-level navigation. The SDKs post a form or nothing from the issuer's own
// page, and a relying party navigates here by GET or by POST.
func TestEnds(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Request
		ends bool
	}{
		{"@hanzo/iam end(): a form fetch from the issuer's page",
			Request{Method: "POST", Site: "same-origin", Mode: "cors", Dest: "empty", Type: "application/x-www-form-urlencoded"}, true},
		{"a bodyless fetch from the issuer's page", Request{Method: "POST", Site: "same-origin", Mode: "cors", Dest: "empty"}, true},
		{"JSON from the issuer's page", Request{Method: "POST", Site: "same-origin", Type: "application/json"}, true},
		{"the person typed the address", Request{Method: "GET", Site: "none", Mode: "navigate", Dest: "document"}, true},
		{"a relying party's sign-out link", Request{Method: "GET", Site: "cross-site", Mode: "navigate", Dest: "document"}, true},
		{"a relying party's sign-out form (RP-Initiated Logout §2)",
			Request{Method: "POST", Site: "same-site", Mode: "navigate", Dest: "document", Type: "application/x-www-form-urlencoded"}, true},
		{"a browser with no Fetch Metadata", Request{Method: "POST", Origin: "https://cloud.hanzo.ai", Type: "application/x-www-form-urlencoded"}, true},
		{"a program", Request{Method: "POST"}, true},
		{"a sibling's image", Request{Method: "GET", Site: "same-site", Mode: "no-cors", Dest: "image"}, false},
		{"a sibling's frame", Request{Method: "GET", Site: "same-site", Mode: "navigate", Dest: "iframe"}, false},
		{"a sibling's fetch", Request{Method: "POST", Site: "same-site", Mode: "cors", Dest: "empty", Type: "application/x-www-form-urlencoded"}, false},
		{"another site's fetch", Request{Method: "POST", Site: "cross-site", Mode: "no-cors", Dest: "empty"}, false},
	} {
		if got := tc.r.ends(); got != tc.ends {
			t.Errorf("%s: ends() = %v, want %v", tc.name, got, tc.ends)
		}
	}
}

// Writer resolves the session only past the rule, and a request with no cookie is
// no caller rather than a refusal, so a bearer can still answer it.
func TestWriterValue(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "alice", "")
	ctx := context.Background()

	if sc, err := WriterValue(ctx, value, Request{Method: http.MethodPost, Site: "same-origin", Type: "application/json"}, h.db); err != nil || sc == nil || sc.Name != "alice" {
		t.Fatalf("the issuer's page: %+v %v, want alice", sc, err)
	}
	if sc, err := WriterValue(ctx, value, Request{Method: http.MethodPost, Site: "same-site", Type: "application/json"}, h.db); !errors.Is(err, ErrForgeable) || sc != nil {
		t.Fatalf("a sibling host: %+v %v, want ErrForgeable", sc, err)
	}
	if sc, err := WriterValue(ctx, "", Request{Method: http.MethodPost, Site: "same-site", Type: "application/x-www-form-urlencoded"}, h.db); err != nil || sc != nil {
		t.Fatalf("no cookie: %+v %v, want no caller and no refusal", sc, err)
	}
	if sc, err := WriterValue(ctx, "garbage.notacookie", Request{Method: http.MethodPost, Site: "same-origin", Type: "application/json"}, h.db); err != nil || sc != nil {
		t.Fatalf("a dead cookie: %+v %v, want no caller", sc, err)
	}
}

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
// person, and a JSON body when there is a body.
func TestForgeable(t *testing.T) {
	for _, tc := range []struct {
		method, site, contentType string
		forgeable                 bool
	}{
		{http.MethodPost, "same-origin", "application/json", false},
		{http.MethodPut, "same-origin", "application/json; charset=utf-8", false},
		{http.MethodPost, "none", "application/json", false},
		{http.MethodGet, "same-origin", "", false},
		{http.MethodPost, "same-site", "application/json", true},
		{http.MethodPost, "cross-site", "application/json", true},
		{http.MethodPost, "", "application/json", true},
		{http.MethodGet, "same-site", "", true},
		{http.MethodGet, "", "", true},
		{http.MethodPost, "same-origin", "application/x-www-form-urlencoded", true},
		{http.MethodPost, "same-origin", "multipart/form-data; boundary=b", true},
		{http.MethodPost, "same-origin", "text/plain", true},
		{http.MethodPost, "same-origin", "", true},
		{http.MethodPost, "same-origin", "application/jsonp", true},
	} {
		if got := Forgeable(tc.method, tc.site, tc.contentType); got != tc.forgeable {
			t.Errorf("Forgeable(%s, %q, %q) = %v, want %v", tc.method, tc.site, tc.contentType, got, tc.forgeable)
		}
	}
}

// Writer resolves the session only past the rule, and a request with no cookie is
// no caller rather than a refusal, so a bearer can still answer it.
func TestWriterValue(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "alice", "")
	ctx := context.Background()

	if sc, err := WriterValue(ctx, value, http.MethodPost, "same-origin", "application/json", h.db); err != nil || sc == nil || sc.Name != "alice" {
		t.Fatalf("the issuer's page: %+v %v, want alice", sc, err)
	}
	if sc, err := WriterValue(ctx, value, http.MethodPost, "same-site", "application/json", h.db); !errors.Is(err, ErrForgeable) || sc != nil {
		t.Fatalf("a sibling host: %+v %v, want ErrForgeable", sc, err)
	}
	if sc, err := WriterValue(ctx, "", http.MethodPost, "same-site", "application/x-www-form-urlencoded", h.db); err != nil || sc != nil {
		t.Fatalf("no cookie: %+v %v, want no caller and no refusal", sc, err)
	}
	if sc, err := WriterValue(ctx, "garbage.notacookie", http.MethodPost, "same-origin", "application/json", h.db); err != nil || sc != nil {
		t.Fatalf("a dead cookie: %+v %v, want no caller", sc, err)
	}
}

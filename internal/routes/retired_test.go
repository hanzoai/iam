// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// WHERE the retirement notices are mounted, and whether they point anywhere —
// the two things internal/gone cannot answer about itself.
//
// They sit on the public group, ahead of the Guard. A stale client holds no
// bearer for a service it has not talked to since the rename, so if these were
// gated it would get 401 and never learn its address moved: the notice would
// exist and reach nobody.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/gone"
	"github.com/hanzoai/iam/internal/testhttp"
)

// A retired address answers 410 with NO credential at all.
func TestRetiredAddressAnswersWithoutABearer(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest("GET", "/v1/iam/get-users", nil)
	req.Host = "hanzo.id"
	status, body := h.do(t, req)
	if status != http.StatusGone {
		t.Fatalf("unauthenticated GET /v1/iam/get-users = %d (%s), want 410 — a notice behind the Guard reaches nobody", status, body)
	}
}

// 410 and 404 say different things and the router keeps them apart: a retired
// address went somewhere, an unknown one never existed. Without the contrast the
// notice is indistinguishable from a typo, which is what sends a caller hunting.
func TestRetiredIsNotTheSameAsUnknown(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest("GET", "/v1/iam/get-nonsense", nil)
	req.Host = "hanzo.id"
	if status, _ := h.do(t, req); status != http.StatusNotFound {
		t.Fatalf("an address nothing ever served = %d, want 404", status)
	}
}

// EVERY SUCCESSOR IS SERVED. A retirement that points at a 404 is worse than no
// notice: it sends a caller to a second dead end with the service's own
// authority behind it.
//
// The retired set comes from the ROUTER and each successor comes off the WIRE,
// out of the Link header the caller actually reads — so this rehearses the
// caller's own move rather than comparing one table against another.
func TestEverySuccessorIsServed(t *testing.T) {
	h := newHarness(t)

	served := map[string]bool{}
	var retired []string
	for _, r := range h.app.Fiber().GetRoutes(true) {
		served[r.Path] = true
		if r.Method == http.MethodGet && gone.Retired(r.Path) {
			retired = append(retired, r.Path)
		}
	}
	if len(retired) == 0 {
		t.Fatal("the router serves no retirement notice — nothing was exercised")
	}

	for _, path := range retired {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "hanzo.id"
		resp, err := testhttp.Do(h.app, req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusGone {
			t.Errorf("%s = %d, want 410", path, resp.StatusCode)
			continue
		}
		targets := successorsOf(resp.Header.Values("Link"))
		if len(targets) == 0 {
			t.Errorf("%s answered 410 naming nowhere to go", path)
			continue
		}
		for _, to := range targets {
			if !served[to] {
				t.Errorf("%s points at %s, which the router does not serve", path, to)
			}
			if gone.Retired(to) {
				t.Errorf("%s points at %s, which is itself retired", path, to)
			}
		}
	}
}

// successorsOf pulls the rel="successor-version" targets out of Link header
// values (RFC 8288: several fields, and several links per field).
func successorsOf(headers []string) []string {
	var out []string
	for _, h := range headers {
		for _, link := range strings.Split(h, ",") {
			parts := strings.Split(link, ";")
			if len(parts) < 2 {
				continue
			}
			rel := false
			for _, p := range parts[1:] {
				if strings.TrimSpace(p) == `rel="successor-version"` {
					rel = true
				}
			}
			if !rel {
				continue
			}
			out = append(out, strings.Trim(strings.TrimSpace(parts[0]), "<>"))
		}
	}
	return out
}

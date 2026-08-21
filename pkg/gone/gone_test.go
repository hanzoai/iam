// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package gone

// The table and the handler, over a bare app. WHERE these are mounted is a
// different question and internal/routes asks it.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zap-proto/zip"
)

func app(t *testing.T) *zip.App {
	t.Helper()
	a := zip.New(zip.Config{AppName: "gone-test", DisableStartupMessage: true})
	Route(a)
	if err := a.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return a
}

func call(t *testing.T, a *zip.App, method, path string) *http.Response {
	t.Helper()
	resp, err := a.Test(httptest.NewRequest(method, path, nil), zip.TestConfig{Timeout: time.Minute, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// EVERY ENTRY ANSWERS THE SAME WAY. A retirement a caller has to special-case is
// not a contract, so the shape is asserted over the whole table rather than a
// sample: 410, the successors in a Link header the caller can parse, and the
// same successors in the body so a person reading a terminal is told too.
func TestEveryRetiredAddressSaysWhereItWent(t *testing.T) {
	a := app(t)
	if len(successor) == 0 {
		t.Fatal("the table is empty")
	}

	for path, to := range successor {
		resp := call(t, a, http.MethodGet, path)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusGone {
			t.Errorf("%s = %d, want 410 (404 reads as a typo)", path, resp.StatusCode)
			continue
		}
		link := resp.Header.Get("Link")
		for _, s := range to {
			if !strings.Contains(link, "<"+s+`>; rel="successor-version"`) {
				t.Errorf("%s: Link %q does not name %s", path, link, s)
			}
		}
		var got notice
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("%s: body is not the notice: %v (%s)", path, err, body)
			continue
		}
		if strings.Join(got.Successor, " ") != strings.Join(to, " ") {
			t.Errorf("%s: body names %v, header names %v", path, got.Successor, to)
		}
	}
}

// THE ADDRESS IS GONE, NOT ONE METHOD ON IT. A caller that sent the wrong method
// would otherwise get a 405 carrying no successor, which is the dead end this
// package exists to remove.
func TestEveryMethodIsGone(t *testing.T) {
	a := app(t)
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		resp := call(t, a, m, "/v1/iam/get-users")
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusGone {
			t.Errorf("%s /v1/iam/get-users = %d, want 410", m, resp.StatusCode)
		}
	}
}

// The two stamps are well-formed and agree with each other: Deprecation is an
// RFC 9651 Date item (RFC 9745), Sunset is an HTTP-date (RFC 8594), and Sunset
// is not earlier than Deprecation (RFC 9745, section 4).
func TestTheStampsAreWellFormed(t *testing.T) {
	resp := call(t, app(t), http.MethodGet, "/v1/iam/get-users")
	_ = resp.Body.Close()

	dep := resp.Header.Get("Deprecation")
	if !strings.HasPrefix(dep, "@") {
		t.Fatalf("Deprecation = %q, want an sf-date (@<seconds>)", dep)
	}
	secs, err := strconv.ParseInt(dep[1:], 10, 64)
	if err != nil {
		t.Fatalf("Deprecation = %q: %v", dep, err)
	}
	sunset, err := time.Parse(http.TimeFormat, resp.Header.Get("Sunset"))
	if err != nil {
		t.Fatalf("Sunset = %q: %v", resp.Header.Get("Sunset"), err)
	}
	if sunset.Before(time.Unix(secs, 0)) {
		t.Errorf("Sunset %s precedes Deprecation %s", sunset, time.Unix(secs, 0).UTC())
	}
}

// A RETIREMENT CANNOT POINT AT A RETIREMENT. Following the chain has to end at
// something that answers, and one hop is the only length a caller will walk.
func TestNoSuccessorIsItselfRetired(t *testing.T) {
	for path, to := range successor {
		for _, s := range to {
			if _, ok := successor[s]; ok {
				t.Errorf("%s points at %s, which is also retired", path, s)
			}
		}
	}
}

// The successor is a URI, not a template. A Link target with {owner} in it is
// unparseable (RFC 3986 forbids the braces), so the successor is the RESOURCE and
// the document teaches how to address one item within it.
func TestSuccessorsAreAddresses(t *testing.T) {
	for path, to := range successor {
		for _, s := range to {
			if !strings.HasPrefix(s, "/v1/iam/") || strings.ContainsAny(s, "{}?<> ") {
				t.Errorf("%s points at %q, which is not an address a Link header can carry", path, s)
			}
		}
	}
}

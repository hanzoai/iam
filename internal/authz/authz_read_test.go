// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz_test

// Read-path authorization, driven through the REAL mounted router. A status code
// is not the contract here — the BODY is: a listing that returns 200 while
// carrying the admin signing key is a total compromise. Every case asserts on
// what actually crossed the wire.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// doBody is do() plus the response body — the read surface's real contract.
func (h *harness) doBody(t *testing.T, method, path, bearer string, body any) (int, string) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := h.app.Fiber().Test(req, testBudget)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// leaks reports whether a response body carries private key material.
func leaks(body string) bool {
	return strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, `"privateKey":"-`)
}

// TestCertPrivateKeyNeverLeaks is the PoC that proved a full token-forgery
// compromise: a hanzo org admin listed certs and received the admin trust
// anchor's private key. Two independent defects composed into it — the listing
// ignored its owner (a GET binds no query, so in.Owner was always "", and an
// empty owner listed EVERY tenant), and the response serialized privateKey. Both
// are closed: the owner is resolved from the verified bearer (authz.Scope), and
// a Cert is masked on the way out (schema.Cert.Mask), so the key material that
// signs every token cannot cross the API at all — a relying party reads the
// PUBLIC half from the JWKS (RFC 7517).
func TestCertPrivateKeyNeverLeaks(t *testing.T) {
	h := newHarness(t)
	anchor := rsaKeyToPEM(t, h.key) // the admin signing cert's real private key

	t.Run("the org-admin PoC leaks neither key material nor another tenant's cert", func(t *testing.T) {
		status, body := h.doBody(t, "GET", "/v1/iam/certs?owner=hanzo", h.token(t, "hanzo/boss"), nil)
		if status != 200 {
			t.Fatalf("own-org listing must succeed, got %d: %s", status, body)
		}
		if strings.Contains(body, anchor) || leaks(body) {
			t.Fatal("LEAK: admin signing key material in an org-admin listing")
		}
		if strings.Contains(body, signingKid) {
			t.Fatal("CROSS-TENANT: the admin-owned cert appeared in a hanzo listing")
		}
	})

	t.Run("a query owner cannot widen the listing past the bearer", func(t *testing.T) {
		// Ask for the admin org explicitly: the guard denies the cross-tenant
		// read, and even if it did not, Scope binds the listing to hanzo.
		status, body := h.doBody(t, "GET", "/v1/iam/certs?owner=admin", h.token(t, "hanzo/boss"), nil)
		if status == 200 && (strings.Contains(body, signingKid) || leaks(body)) {
			t.Fatalf("LEAK: querying owner=admin escaped the bearer's scope: %s", body)
		}
	})

	t.Run("SuperAdmin reads every tenant but never key material", func(t *testing.T) {
		status, body := h.doBody(t, "GET", "/v1/iam/certs", h.token(t, "admin/root"), nil)
		if status != 200 {
			t.Fatalf("SuperAdmin listing must succeed, got %d: %s", status, body)
		}
		if !strings.Contains(body, signingKid) {
			t.Fatalf("SuperAdmin must still SEE the cert (masked, not hidden): %s", body)
		}
		if strings.Contains(body, anchor) || leaks(body) {
			t.Fatal("LEAK: key material served to SuperAdmin — the key never leaves the store")
		}
	})

	t.Run("an unscoped listing by a tenant is refused, never lists-all", func(t *testing.T) {
		status, body := h.doBody(t, "GET", "/v1/iam/certs", h.token(t, "hanzo/boss"), nil)
		if status == 200 && strings.Contains(body, signingKid) {
			t.Fatalf("LEAK: an empty owner listed every tenant: %s", body)
		}
	})

	t.Run("the JWKS still publishes the PUBLIC half at both paths", func(t *testing.T) {
		// The keys are masked out of the CRUD surface, not out of the protocol:
		// the gateway defaults to the root path, the SDK reads the /v1/iam one.
		for _, p := range []string{"/.well-known/jwks", "/v1/iam/.well-known/jwks"} {
			status, body := h.doBody(t, "GET", p, "", nil)
			if status != 200 {
				t.Fatalf("%s must be public and serve keys, got %d", p, status)
			}
			if !strings.Contains(body, `"kty":"RSA"`) || !strings.Contains(body, signingKid) {
				t.Fatalf("%s must publish the signing key: %s", p, body)
			}
			if leaks(body) || strings.Contains(body, `"d":`) {
				t.Fatalf("LEAK: %s served private material: %s", p, body)
			}
		}
	})
}

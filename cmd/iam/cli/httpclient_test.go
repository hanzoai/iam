// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// roundTrip spins up a one-shot httptest.Server and runs fn against an
// HTTPClient pointed at it. Used to assert envelope decoding without
// hitting a live IAM.
func roundTrip(t *testing.T, h http.HandlerFunc, fn func(*HTTPClient)) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := &Config{Addr: srv.URL, Token: "test-token"}
	fn(NewHTTPClient(cfg))
}

func TestGet_EnvelopeOk(t *testing.T) {
	roundTrip(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","msg":"","data":[{"clientId":"abc"}]}`)
	}, func(c *HTTPClient) {
		var out []Application
		if err := c.Get("/v1/iam/get-applications", nil, &out); err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(out) != 1 || out[0].ClientId != "abc" {
			t.Errorf("out = %v", out)
		}
	})
}

func TestGet_EnvelopeError(t *testing.T) {
	roundTrip(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"error","msg":"nope","data":null}`)
	}, func(c *HTTPClient) {
		var out []Application
		err := c.Get("/v1/iam/get-applications", nil, &out)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("want *APIError, got %T", err)
		}
		if apiErr.Message != "nope" {
			t.Errorf("apiErr.Message = %q, want nope", apiErr.Message)
		}
	})
}

func TestGet_HTTPError(t *testing.T) {
	roundTrip(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"status":"error","msg":"missing token"}`)
	}, func(c *HTTPClient) {
		err := c.Get("/v1/iam/get-applications", nil, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("want *APIError, got %T", err)
		}
		if apiErr.Status != http.StatusUnauthorized {
			t.Errorf("apiErr.Status = %d, want 401", apiErr.Status)
		}
		if apiErr.Message != "missing token" {
			t.Errorf("apiErr.Message = %q, want missing token", apiErr.Message)
		}
	})
}

func TestPostJSON_BootstrapResponseShape(t *testing.T) {
	// Bootstrap upsert returns { status: ok, action: ..., data: { ... } }
	// instead of the standard { status: ok, data: ... } shape. The client
	// must accept either.
	roundTrip(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","action":"created","data":{"clientId":"abc"}}`)
	}, func(c *HTTPClient) {
		if err := c.PostJSON("/v1/iam/admin/applications/upsert", nil, map[string]string{"name": "x"}, nil); err != nil {
			t.Fatalf("PostJSON: %v", err)
		}
	})
}

func TestRequireToken_Unset(t *testing.T) {
	cfg := (&Config{}).resolve()
	cfg.Token = ""
	err := cfg.RequireToken()
	if err == nil {
		t.Fatal("expected error when token unset")
	}
	if !strings.Contains(err.Error(), "IAM_TOKEN") {
		t.Errorf("error doesn't mention IAM_TOKEN: %v", err)
	}
	if !strings.Contains(err.Error(), "IAM_SERVICE_TOKEN") {
		t.Errorf("error doesn't tell operator where to find a token: %v", err)
	}
}

func TestRequireToken_Set(t *testing.T) {
	cfg := &Config{Token: "abc"}
	if err := cfg.RequireToken(); err != nil {
		t.Errorf("RequireToken with token set: %v", err)
	}
}

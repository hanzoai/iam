// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config carries the IAM server address + bearer token resolved from the
// environment and/or top-level flags. One instance is built in cli.go and
// shared by every subcommand.
type Config struct {
	Addr  string
	Token string
}

// resolve returns the final Config, applying env fallbacks and trimming.
// IAM_ADDR defaults to http://localhost:8000. IAM_TOKEN has no default —
// authenticated commands fail loudly if it's unset (see RequireToken).
func (cfg *Config) resolve() *Config {
	out := &Config{
		Addr:  strings.TrimSpace(cfg.Addr),
		Token: strings.TrimSpace(cfg.Token),
	}
	if out.Addr == "" {
		out.Addr = os.Getenv("IAM_ADDR")
	}
	if out.Addr == "" {
		out.Addr = "http://localhost:8000"
	}
	out.Addr = strings.TrimRight(out.Addr, "/")
	if out.Token == "" {
		out.Token = os.Getenv("IAM_TOKEN")
	}
	return out
}

// RequireToken returns an error pointing the operator at how to find a
// service token if IAM_TOKEN is unset. Every authenticated subcommand
// calls this before issuing a request.
func (cfg *Config) RequireToken() error {
	if strings.TrimSpace(cfg.Token) != "" {
		return nil
	}
	return fmt.Errorf(`iam: no bearer token configured.

Set IAM_TOKEN (or pass --token=...) before running authenticated commands.

In a Liquidity cluster:
  export IAM_TOKEN=$(kubectl --context=gke_liquidity-devnet_us-central1_dev \
                     -n liquidity exec deploy/ -- printenv IAM_SERVICE_TOKEN)

In a Hanzo cluster:
  export IAM_TOKEN=$(kubectl -n hanzo exec deploy/hanzo-iam -- printenv IAM_SERVICE_TOKEN)

Locally (compose / kind):
  export IAM_TOKEN=$(docker compose exec  printenv IAM_SERVICE_TOKEN)`)
}

// APIError is the error returned when IAM responds with a non-2xx, or
// when its status="error" envelope flags a logical failure. Mirrors the
// TypeScript HanzoAPIError shape used by @hanzo/sdk so callers can pattern-
// match on Status (HTTP) and Message (server msg) the same way.
type APIError struct {
	Status     int
	StatusText string
	Message    string
	Body       []byte
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("iam: %d %s: %s", e.Status, e.StatusText, e.Message)
	}
	return fmt.Sprintf("iam: %d %s", e.Status, e.StatusText)
}

// HTTPClient wraps a *http.Client with the IAM-specific Bearer token,
// envelope handling, and URL builder.
type HTTPClient struct {
	cfg *Config
	c   *http.Client
}

func NewHTTPClient(cfg *Config) *HTTPClient {
	return &HTTPClient{
		cfg: cfg.resolve(),
		c: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (h *HTTPClient) Addr() string { return h.cfg.Addr }

func (h *HTTPClient) url(path string, query url.Values) string {
	u := h.cfg.Addr + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

// envelope mirrors controllers/account.go Response. The data field is
// preserved as raw JSON so subcommands can decode it into their own
// strongly-typed payload structs.
type envelope struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Sub    string          `json:"sub"`
	Name   string          `json:"name"`
	Data   json.RawMessage `json:"data"`
	Data2  json.RawMessage `json:"data2"`
}

// Get issues a GET, unwraps the IAM envelope, and decodes data into out.
// Pass out=nil to discard the body.
func (h *HTTPClient) Get(path string, query url.Values, out any) error {
	req, err := http.NewRequest(http.MethodGet, h.url(path, query), nil)
	if err != nil {
		return err
	}
	return h.do(req, out)
}

// PostJSON issues a POST with JSON body, unwraps the envelope, decodes
// data into out (nil to discard).
func (h *HTTPClient) PostJSON(path string, query url.Values, body any, out any) error {
	var buf io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, h.url(path, query), buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return h.do(req, out)
}

// PostRaw issues a POST with raw bytes (caller-controlled JSON file).
func (h *HTTPClient) PostRaw(path string, query url.Values, body []byte, out any) error {
	req, err := http.NewRequest(http.MethodPost, h.url(path, query), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return h.do(req, out)
}

func (h *HTTPClient) do(req *http.Request, out any) error {
	if h.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.cfg.Token)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		return fmt.Errorf("iam: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("iam: read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to extract envelope.msg for a richer message.
		msg := ""
		var env envelope
		if jerr := json.Unmarshal(body, &env); jerr == nil && env.Msg != "" {
			msg = env.Msg
		}
		return &APIError{
			Status:     resp.StatusCode,
			StatusText: resp.Status,
			Message:    msg,
			Body:       body,
		}
	}

	// 2xx — most endpoints return the IAM envelope; bootstrap upserts
	// + a few raw responses return naked JSON. Decode as envelope first;
	// if status is empty, treat the whole body as the payload.
	var env envelope
	if jerr := json.Unmarshal(body, &env); jerr != nil {
		// Not envelope-shaped at all — pass the raw body to out.
		if out == nil {
			return nil
		}
		return json.Unmarshal(body, out)
	}
	if env.Status == "error" {
		return &APIError{
			Status:     resp.StatusCode,
			StatusText: resp.Status,
			Message:    env.Msg,
			Body:       body,
		}
	}
	if out == nil {
		return nil
	}
	if env.Status == "" {
		// Bootstrap-style response: { "status": "ok", ... } with top-level fields.
		// Re-decode the whole body into out.
		return json.Unmarshal(body, out)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

// printJSON pretty-prints v to stdout. Used by every --json flag.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

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
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// The provisioning subcommands (init-apps, init-providers, wire-providers,
// clean-spam-orgs) authenticate differently from the interactive `iam app/
// user/org` tree. Those use a Bearer service token (--token / IAM_TOKEN);
// these run as one-shot Kubernetes Jobs that reconcile IAM from KMS-sourced
// configuration and authenticate with the Casdoor-style clientId/clientSecret
// query-parameter scheme of an admin application.
//
// IAM's auto-signin filter (routers/base.go getUsernameByClientIdSecret)
// resolves a matching clientId+clientSecret to the session user "app/<name>",
// and IsAppUser("app/...") grants global-admin — exactly the privilege
// add-provider / update-application / delete-organization require. So ANY
// valid app credential works; the deploy wires the admin/provisioning app's
// id+secret (KMS-sourced) into the Job env.
//
// Keeping this its own client (separate from httpclient.go) is deliberate:
// two auth models, two concerns, one way each. No braiding.

// provConfig is the canonical view of the provisioning subcommands' runtime
// configuration. All fields derive from environment variables. Construction
// is the only validation step: once a provConfig exists, ClientID and
// ClientSecret are guaranteed non-empty.
type provConfig struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	AdminOrg     string
}

// loadProvEnv reads the provisioning configuration from the environment.
// IAM_ENDPOINT defaults to http://localhost:8000; IAM_ADMIN_ORG to "admin".
// IAM_CLIENT_ID / IAM_CLIENT_SECRET are required (admin app, KMS-sourced).
func loadProvEnv() (*provConfig, error) {
	c := &provConfig{
		Endpoint:     provEnvOrDefault("IAM_ENDPOINT", "http://localhost:8000"),
		ClientID:     strings.TrimSpace(os.Getenv("IAM_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("IAM_CLIENT_SECRET")),
		AdminOrg:     provEnvOrDefault("IAM_ADMIN_ORG", "admin"),
	}
	if c.ClientID == "" {
		return nil, fmt.Errorf("IAM_CLIENT_ID is required")
	}
	if c.ClientSecret == "" {
		return nil, fmt.Errorf("IAM_CLIENT_SECRET is required")
	}
	c.Endpoint = strings.TrimRight(c.Endpoint, "/")
	return c, nil
}

func provEnvOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// provClient is a thin HTTP wrapper around the canonical /v1/iam/* API that
// injects clientId/clientSecret on every request. Jobs are short-lived and
// stateless, so we inject per-call rather than holding a session.
type provClient struct {
	cfg  *provConfig
	http *http.Client
}

func newProvClient(cfg *provConfig) *provClient {
	return &provClient{
		cfg:  cfg,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// withAuth returns the URL with clientId/clientSecret query params appended.
func (c *provClient) withAuth(rel string, extra url.Values) string {
	u, _ := url.Parse(c.cfg.Endpoint + rel)
	q := u.Query()
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	q.Set("clientId", c.cfg.ClientID)
	q.Set("clientSecret", c.cfg.ClientSecret)
	u.RawQuery = q.Encode()
	return u.String()
}

// provResp is IAM's canonical envelope: {"status":"ok","data":...} or
// {"status":"error","msg":"..."}. data is RawMessage so callers decode into
// their own typed shapes.
type provResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func (c *provClient) get(rel string, q url.Values, out any) error {
	resp, err := c.http.Get(c.withAuth(rel, q))
	if err != nil {
		return fmt.Errorf("GET %s: %w", rel, err)
	}
	defer resp.Body.Close()
	return provDecode(resp, rel, out)
}

func (c *provClient) postJSON(rel string, q url.Values, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal body: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.withAuth(rel, q), bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", rel, err)
	}
	defer resp.Body.Close()
	return provDecode(resp, rel, out)
}

func provDecode(resp *http.Response, rel string, out any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", rel, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: http %d: %s", rel, resp.StatusCode, provTruncate(string(body), 200))
	}
	var env provResp
	if err := json.Unmarshal(body, &env); err != nil {
		// Some endpoints return the raw payload — fall back to direct decode.
		if out != nil {
			return json.Unmarshal(body, out)
		}
		return nil
	}
	if env.Status != "" && env.Status != "ok" {
		return fmt.Errorf("%s: api error: %s", rel, env.Msg)
	}
	if out != nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

func provTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// newProvisionVerboseFlag attaches the shared `-v/--verbose` flag every
// provisioning subcommand exposes and returns a pointer to its value.
func newProvisionVerboseFlag(cmd *cobra.Command) *bool {
	return cmd.Flags().BoolP("verbose", "v", false, "verbose logging")
}

// atoiEnv reads an integer env var, returning def when unset/empty and an
// error when set but unparseable.
func atoiEnv(key string, def int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q: %w", v, err)
	}
	return n, nil
}

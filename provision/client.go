// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package provision

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Env is the reconciler's runtime configuration, drawn entirely from the
// environment so the same binary serves the CLI, a one-shot Job and the server
// boot path. Endpoint defaults to the local server; AdminOrg to "admin".
// ClientID/ClientSecret are an admin application's credentials (KMS-sourced).
type Env struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	AdminOrg     string
	ConfigPath   string
}

// LoadEnv reads the reconciler configuration from the environment. It mirrors
// the credential scheme the other IAM provisioning commands use:
// IAM_ENDPOINT, IAM_CLIENT_ID, IAM_CLIENT_SECRET, IAM_ADMIN_ORG, plus
// IAM_PROVISION_CONFIG for the declarative document.
func LoadEnv() (*Env, error) {
	e := &Env{
		Endpoint:     envOr("IAM_ENDPOINT", "http://localhost:8000"),
		ClientID:     strings.TrimSpace(os.Getenv("IAM_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("IAM_CLIENT_SECRET")),
		AdminOrg:     envOr("IAM_ADMIN_ORG", defaultOwner),
		ConfigPath:   strings.TrimSpace(os.Getenv("IAM_PROVISION_CONFIG")),
	}
	if e.ClientID == "" {
		return nil, fmt.Errorf("IAM_CLIENT_ID is required")
	}
	if e.ClientSecret == "" {
		return nil, fmt.Errorf("IAM_CLIENT_SECRET is required")
	}
	e.Endpoint = strings.TrimRight(e.Endpoint, "/")
	return e, nil
}

// Client returns the HTTP IAM client this Env describes.
func (e *Env) Client() *Client {
	return &Client{
		endpoint: e.Endpoint,
		clientID: e.ClientID,
		secret:   e.ClientSecret,
		adminOrg: e.AdminOrg,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// RunFromEnv loads the environment and the declared config, then reconciles. An
// empty config (no IAM_PROVISION_CONFIG, or a document with no orgs) is a clean
// no-op. This is the CLI entry point.
func RunFromEnv(verbose bool) (Result, error) {
	env, err := LoadEnv()
	if err != nil {
		return Result{}, err
	}
	cfg, err := LoadConfig(env.ConfigPath)
	if err != nil {
		return Result{}, err
	}
	if len(cfg.Orgs) == 0 {
		return Result{}, nil
	}
	return Reconcile(env.Client(), cfg, env.AdminOrg, verbose)
}

// ProvisionOnBoot reconciles the declarative config against this server's own
// API when IAM_PROVISION_ON_BOOT is truthy. It is best-effort by design: it
// waits for the server to become healthy, then reconciles, logging — never
// panicking — on any failure, so a provisioning hiccup can never stop IAM from
// serving. Intended to run in a background goroutine from server startup.
func ProvisionOnBoot() {
	if !boolEnv("IAM_PROVISION_ON_BOOT") {
		return
	}
	env, err := LoadEnv()
	if err != nil {
		log.Printf("provision: boot skipped: %v", err)
		return
	}
	if env.ConfigPath == "" {
		log.Printf("provision: boot skipped: IAM_PROVISION_CONFIG is unset")
		return
	}
	cfg, err := LoadConfig(env.ConfigPath)
	if err != nil {
		log.Printf("provision: boot config error: %v", err)
		return
	}
	if len(cfg.Orgs) == 0 {
		log.Printf("provision: boot: config declares no orgs, nothing to do")
		return
	}
	if err := waitHealthy(env.Endpoint, 90*time.Second); err != nil {
		log.Printf("provision: boot skipped: server not healthy: %v", err)
		return
	}
	res, err := Reconcile(env.Client(), cfg, env.AdminOrg, false)
	if err != nil {
		log.Printf("provision: boot reconcile error: %v", err)
		return
	}
	log.Printf("provision: boot ok — orgs +%d, apps +%d, %d already present",
		res.OrgsCreated, res.AppsCreated, res.AppsPresent)
}

// Client is a thin HTTP wrapper over the canonical /v1/iam admin API. It
// authenticates every request with the admin application's clientId/
// clientSecret query parameters — the same scheme IAM's auto-signin filter
// resolves to a global-admin session.
type Client struct {
	endpoint string
	clientID string
	secret   string
	adminOrg string
	http     *http.Client
}

// nameRow captures just the row name from a list endpoint — all the reconciler
// needs to decide whether an org or app already exists.
type nameRow struct {
	Name string `json:"name"`
}

// OrgNames implements IAM.
func (c *Client) OrgNames() ([]string, error) {
	q := url.Values{"owner": {c.adminOrg}}
	var rows []nameRow
	if err := c.get("/v1/iam/get-organizations", q, &rows); err != nil {
		return nil, err
	}
	return rowNames(rows), nil
}

// AppNames implements IAM.
func (c *Client) AppNames(org string) ([]string, error) {
	q := url.Values{"owner": {c.adminOrg}, "organization": {org}}
	var rows []nameRow
	if err := c.get("/v1/iam/get-applications", q, &rows); err != nil {
		return nil, err
	}
	return rowNames(rows), nil
}

// AddOrg implements IAM.
func (c *Client) AddOrg(o *OrgPayload) error {
	return c.postJSON("/v1/iam/add-organization", o)
}

// AddApp implements IAM.
func (c *Client) AddApp(a *AppPayload) error {
	return c.postJSON("/v1/iam/add-application", a)
}

func (c *Client) withAuth(rel string, q url.Values) string {
	u, _ := url.Parse(c.endpoint + rel)
	if q == nil {
		q = url.Values{}
	}
	q.Set("clientId", c.clientID)
	q.Set("clientSecret", c.secret)
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) get(rel string, q url.Values, out any) error {
	resp, err := c.http.Get(c.withAuth(rel, q))
	if err != nil {
		return fmt.Errorf("GET %s: %w", rel, err)
	}
	defer resp.Body.Close()
	return decode(resp, rel, out)
}

func (c *Client) postJSON(rel string, body any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal %s body: %w", rel, err)
	}
	req, err := http.NewRequest(http.MethodPost, c.withAuth(rel, nil), bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", rel, err)
	}
	defer resp.Body.Close()
	return decode(resp, rel, nil)
}

// resp is IAM's canonical envelope: {"status":"ok","data":...} or
// {"status":"error","msg":"..."}.
type resp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func decode(r *http.Response, rel string, out any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", rel, err)
	}
	if r.StatusCode/100 != 2 {
		return fmt.Errorf("%s: http %d: %s", rel, r.StatusCode, truncate(string(body), 200))
	}
	var env resp
	if err := json.Unmarshal(body, &env); err != nil {
		// Some endpoints return the raw payload — fall back to a direct decode.
		if out != nil {
			return json.Unmarshal(body, out)
		}
		return nil
	}
	if env.Status != "" && env.Status != "ok" {
		return fmt.Errorf("%s: %s", rel, env.Msg)
	}
	if out != nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

// waitHealthy polls the server's health endpoint until it returns 2xx or the
// timeout elapses.
func waitHealthy(endpoint string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		resp, err := client.Get(endpoint + "/api/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				return nil
			}
			last = fmt.Errorf("health http %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(2 * time.Second)
	}
	if last == nil {
		last = fmt.Errorf("timeout after %s", timeout)
	}
	return last
}

func rowNames(rows []nameRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Name != "" {
			out = append(out, r.Name)
		}
	}
	return out
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func boolEnv(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

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

// envConfig is the canonical view of iamctl's runtime configuration.
// All fields are derived from environment variables. Construction is
// the only validation step — once an envConfig is constructed, fields
// are guaranteed non-empty.
type envConfig struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	AdminOrg     string
}

func loadEnv() (*envConfig, error) {
	c := &envConfig{
		Endpoint:     envOrDefault("IAM_ENDPOINT", "http://localhost:8000"),
		ClientID:     os.Getenv("IAM_CLIENT_ID"),
		ClientSecret: os.Getenv("IAM_CLIENT_SECRET"),
		AdminOrg:     envOrDefault("IAM_ADMIN_ORG", "admin"),
	}
	if c.ClientID == "" {
		return nil, fmt.Errorf("IAM_CLIENT_ID is required")
	}
	if c.ClientSecret == "" {
		return nil, fmt.Errorf("IAM_CLIENT_SECRET is required")
	}
	// Trim trailing slash for stable URL composition.
	c.Endpoint = strings.TrimRight(c.Endpoint, "/")
	return c, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// iamClient is a thin HTTP wrapper around the canonical /v1/iam/* API.
//
// Auth model: IAM (Casdoor-derived) accepts service-to-service auth via
// clientId/clientSecret query parameters appended to every request. We
// inject them on every call rather than holding a session — Jobs are
// short-lived and stateless.
type iamClient struct {
	cfg  *envConfig
	http *http.Client
}

func newClient(cfg *envConfig) *iamClient {
	return &iamClient{
		cfg: cfg,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// withAuth returns the URL with clientId/clientSecret query params appended.
// Caller supplies the relative path (e.g. "/v1/iam/get-applications").
func (c *iamClient) withAuth(rel string, extra url.Values) string {
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

// apiResp is IAM's canonical response envelope: {"status":"ok","data":...}
// or {"status":"error","msg":"..."}. We capture data as RawMessage so
// callers can unmarshal into typed shapes.
type apiResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func (c *iamClient) get(rel string, q url.Values, out interface{}) error {
	resp, err := c.http.Get(c.withAuth(rel, q))
	if err != nil {
		return fmt.Errorf("GET %s: %w", rel, err)
	}
	defer resp.Body.Close()
	return decode(resp, rel, out)
}

func (c *iamClient) postJSON(rel string, q url.Values, body, out interface{}) error {
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
	return decode(resp, rel, out)
}

func decode(resp *http.Response, rel string, out interface{}) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", rel, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: http %d: %s", rel, resp.StatusCode, truncate(string(body), 200))
	}
	var env apiResp
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

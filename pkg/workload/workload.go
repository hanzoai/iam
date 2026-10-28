// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package workload is the native IAM client for an audience-bound pod assertion.
package workload

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Token struct {
	AccessToken string    `json:"access_token"`
	ExpiresIn   int64     `json:"expires_in"`
	Expiry      time.Time `json:"-"`
}

// Exchange uses the native RFC 7523 grant. A refusal never includes the response
// body in its error: token responses carry credentials.
func Exchange(ctx context.Context, issuer, assertion string, client *http.Client) (*Token, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {strings.TrimSpace(assertion)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(issuer, "/")+"/v1/iam/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IAM workload exchange unreachable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("IAM workload exchange answered HTTP %d", res.StatusCode)
	}
	var t Token
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&t) != nil || t.AccessToken == "" {
		return nil, fmt.Errorf("IAM workload exchange returned no token")
	}
	t.Expiry = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	return &t, nil
}

// Pod exchanges the kubelet's rotated, audience-bound assertion. No separate
// client secret is issued to the workload.
func Pod(ctx context.Context) (*Token, error) {
	file := os.Getenv("HANZO_SA_TOKEN")
	if file == "" {
		file = "/var/run/secrets/hanzo/iam/token"
	}
	issuer := os.Getenv("HANZO_IAM_URL")
	if issuer == "" {
		issuer = "https://hanzo.id"
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read native workload assertion: %w", err)
	}
	return Exchange(ctx, issuer, string(b), nil)
}

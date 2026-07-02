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

//go:build !skipCi

// service_account_e2e_test.go — live lifecycle guard for the service-account
// surface reached by a CapKeyMint confidential client via a client_credentials
// JWT (the exact caller shape that was BROKEN in prod: the JWT resolved to
// "<org>/<app>" and missed every "app/<name>"-keyed control, so the SA routes
// default-denied before the controller gate ran).
//
// This exercises the real create → list → rotate → delete lifecycle AND the
// deny paths (anonymous, non-CapKeyMint app) against a live IAM. It is
// env-gated (skips otherwise), matching the other live tests in this package:
//
//	IAM_E2E_URL=https://iam.hanzo.ai \
//	IAM_E2E_CC_CLIENT_ID=<CapKeyMint app clientId, e.g. hanzo-console's> \
//	IAM_E2E_CC_CLIENT_SECRET=<its clientSecret> \
//	IAM_E2E_ORG=hanzo \
//	  go test ./controllers/ -run TestServiceAccountLifecycleE2E -count=1 -v
//
// The clientId's application MUST be allowlisted in IAM_KEY_MINT_ALLOWED_APPS on
// the target IAM for the create/rotate/delete to be authorized.

package controllers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func saHTTP() *http.Client { return &http.Client{Timeout: 20 * time.Second} }

// saClientCredentialsToken performs the OAuth client_credentials grant and
// returns the access token (a confidential-client JWT).
func saClientCredentialsToken(t *testing.T, base, clientId, clientSecret string) string {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid")
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/iam/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientId, clientSecret)
	resp, err := saHTTP().Do(req)
	if err != nil {
		t.Fatalf("client_credentials grant: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("client_credentials grant: non-JSON body: %s", string(body[:min(len(body), 300)]))
	}
	if out.AccessToken == "" {
		t.Fatalf("client_credentials grant returned no access_token (error=%q desc=%q)", out.Error, out.ErrorDesc)
	}
	return out.AccessToken
}

func saDo(t *testing.T, method, url, token string, body io.Reader) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(method, url, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := saHTTP().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s %s: non-JSON body: %s", method, url, string(raw[:min(len(raw), 300)]))
	}
	return out
}

func saDenied(m map[string]any) bool {
	sig := strings.ToLower(saStr(m["status"]) + " " + saStr(m["msg"]))
	return strings.Contains(sig, "unauthorized")
}

func saStr(v any) string { s, _ := v.(string); return s }

func TestServiceAccountLifecycleE2E(t *testing.T) {
	base := strings.TrimRight(os.Getenv("IAM_E2E_URL"), "/")
	clientId := os.Getenv("IAM_E2E_CC_CLIENT_ID")
	clientSecret := os.Getenv("IAM_E2E_CC_CLIENT_SECRET")
	org := os.Getenv("IAM_E2E_ORG")
	if base == "" || clientId == "" || clientSecret == "" || org == "" {
		t.Skip("skipping: set IAM_E2E_URL + IAM_E2E_CC_CLIENT_ID + IAM_E2E_CC_CLIENT_SECRET + IAM_E2E_ORG")
	}

	token := saClientCredentialsToken(t, base, clientId, clientSecret)

	// --- DENY: anonymous create must be rejected. ---
	anon := saDo(t, http.MethodPost, base+"/v1/iam/service-accounts", "",
		strings.NewReader(`{"organization":"`+org+`","name":"e2e-probe"}`))
	if !saDenied(anon) {
		t.Fatalf("SECURITY: anonymous create-service-account was NOT denied: %v", anon)
	}

	// --- ALLOW: the CapKeyMint confidential client creates a service account. ---
	agent := "e2e-agent"
	create := saDo(t, http.MethodPost, base+"/v1/iam/service-accounts", token,
		strings.NewReader(`{"organization":"`+org+`","name":"`+agent+`"}`))
	if saStr(create["status"]) != "ok" {
		t.Fatalf("create-service-account denied for CapKeyMint client (the prod bug): %v", create)
	}
	data, _ := create["data"].(map[string]any)
	name := saStr(data["name"])
	if name == "" || saStr(data["accessKey"]) == "" || saStr(data["accessSecret"]) == "" {
		t.Fatalf("create response missing name/accessKey/accessSecret: %v", create["data"])
	}
	t.Logf("created service account %q (org=%s)", name, org)

	// --- LIST: the new SA appears; secrets are never serialized. ---
	list := saDo(t, http.MethodGet, base+"/v1/iam/service-accounts?organization="+org, token, nil)
	if saStr(list["status"]) != "ok" {
		t.Fatalf("list-service-accounts denied: %v", list)
	}

	// --- ROTATE: mint a new key for the SA. ---
	rot := saDo(t, http.MethodPost, base+"/v1/iam/service-accounts/"+name+"/keys?organization="+org, token, nil)
	if saStr(rot["status"]) != "ok" {
		t.Fatalf("rotate-service-account-key denied: %v", rot)
	}

	// --- DELETE: revoke the SA (cleanup + delete-path proof). ---
	del := saDo(t, http.MethodDelete, base+"/v1/iam/service-accounts/"+name+"?organization="+org, token, nil)
	if saStr(del["status"]) != "ok" {
		t.Fatalf("delete-service-account denied: %v", del)
	}
	t.Logf("SA lifecycle create→list→rotate→delete OK via client_credentials JWT (%s)", clientId)
}

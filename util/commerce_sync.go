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

package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/hanzoai/iam/conf"
)

// commerceSyncRequest is the JSON body sent to Commerce's account-sync endpoint.
type commerceSyncRequest struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// getCommerceEndpoint returns the Commerce service URL.
// Reads from env COMMERCE_ENDPOINT, then Beego config "commerceEndpoint".
// Returns empty string if unconfigured (sync is skipped).
func getCommerceEndpoint() string {
	if v := os.Getenv("COMMERCE_ENDPOINT"); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := conf.GetConfigString("commerceEndpoint"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return ""
}

// getCommerceServiceToken returns the shared service token for Commerce.
// Reads from env COMMERCE_SERVICE_TOKEN, then Beego config "commerceServiceToken".
func getCommerceServiceToken() string {
	if v := os.Getenv("COMMERCE_SERVICE_TOKEN"); v != "" {
		return v
	}
	return conf.GetConfigString("commerceServiceToken")
}

// SyncUserToCommerce creates a Commerce account and assigns the free plan
// for a newly signed-up user. This function is designed to be called
// asynchronously (via SafeGoroutine) after IAM signup completes.
//
// It is non-blocking, retry-capable, and idempotent:
//   - Retries up to 3 times with exponential backoff (2s, 4s, 8s).
//   - Commerce's account-sync endpoint returns 200 if the user already exists.
//   - Errors are logged but never propagated to the caller.
func SyncUserToCommerce(owner, name, email string) {
	endpoint := getCommerceEndpoint()
	if endpoint == "" {
		logs.Debug("commerce-sync: skipped (COMMERCE_ENDPOINT not configured)")
		return
	}

	token := getCommerceServiceToken()
	if token == "" {
		logs.Warning("commerce-sync: skipped (COMMERCE_SERVICE_TOKEN not configured)")
		return
	}

	url := endpoint + "/api/v1/billing/account-sync"

	body, err := json.Marshal(commerceSyncRequest{
		Owner: owner,
		Name:  name,
		Email: email,
	})
	if err != nil {
		logs.Error("commerce-sync: failed to marshal request for %s/%s: %v", owner, name, err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}

	var lastErr error
	backoffs := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}

	for attempt := 0; attempt <= len(backoffs); attempt++ {
		if attempt > 0 {
			time.Sleep(backoffs[attempt-1])
		}

		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			logs.Error("commerce-sync: failed to create request for %s/%s: %v", owner, name, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: %w", attempt+1, err)
			logs.Warning("commerce-sync: request failed for %s/%s (attempt %d/%d): %v",
				owner, name, attempt+1, len(backoffs)+1, err)
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			logs.Info("commerce-sync: provisioned Commerce account for %s/%s (status=%d)",
				owner, name, resp.StatusCode)
			return
		}

		lastErr = fmt.Errorf("attempt %d: status %d, body: %s", attempt+1, resp.StatusCode, string(respBody))

		// Do not retry on client errors (4xx) except 408 (timeout) and 429 (rate limit).
		if resp.StatusCode >= 400 && resp.StatusCode < 500 &&
			resp.StatusCode != http.StatusRequestTimeout &&
			resp.StatusCode != http.StatusTooManyRequests {
			logs.Error("commerce-sync: non-retryable error for %s/%s: %v", owner, name, lastErr)
			return
		}

		logs.Warning("commerce-sync: retryable error for %s/%s (attempt %d/%d): %v",
			owner, name, attempt+1, len(backoffs)+1, lastErr)
	}

	logs.Error("commerce-sync: all attempts exhausted for %s/%s: %v", owner, name, lastErr)
}

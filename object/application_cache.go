// Copyright 2024 The Hanzo Authors. All Rights Reserved.
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

package object

// application_cache.go provides an in-process TTL cache for Application objects.
//
// Applications rarely change in production but are fetched multiple times per
// login request (once in the controller, once in CheckOAuthLogin, once for JWT
// generation). Caching eliminates ~9 redundant DB queries per login.
//
// TTL: 5 minutes. Explicit invalidation on UpdateApplication/DeleteApplication.

import "time"

var (
	// appCache stores fully-extended Application objects.
	// Key: "owner/name" (e.g., "admin/app-hanzo")
	// TTL: 5 minutes — application config changes are infrequent.
	appCache = &ttlCache{}

	// appCacheByClientId maps clientId → "owner/name" for client_id lookups.
	appClientIdCache = &ttlCache{}
)

const appCacheTTL = 5 * time.Minute

func appCacheKey(owner, name string) string { return "app:" + owner + "/" + name }

func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			appCache.gc()
			appClientIdCache.gc()
		}
	}()
}

// EvictAppCache removes a cached application. Call after any write.
func EvictAppCache(owner, name string) {
	appCache.delete(appCacheKey(owner, name))
	// We cannot easily evict by clientId without storing the mapping,
	// so we rely on TTL expiry for client_id-based lookups.
}

// EvictAppCacheByClientId removes a cached client_id mapping.
func EvictAppCacheByClientId(clientId string) {
	appClientIdCache.delete("client:" + clientId)
}

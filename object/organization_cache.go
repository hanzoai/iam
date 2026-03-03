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

// organization_cache.go provides an in-process TTL cache for Organization objects.
//
// Organizations are fetched 3+ times per login (extendApplicationWithOrg,
// CheckPassword → GetOrganizationByUser, HandleLoggedIn → GetOrganizationByUser).
// Caching eliminates all redundant DB reads.
//
// TTL: 5 minutes. Explicit invalidation on UpdateOrganization/DeleteOrganization.

import "time"

// orgCache stores Organization objects.
// Key: "org:owner/name"
// TTL: 5 minutes.
var orgCache = &ttlCache{}

const orgCacheTTL = 5 * time.Minute

func orgCacheKey(owner, name string) string { return "org:" + owner + "/" + name }

func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			orgCache.gc()
		}
	}()
}

// EvictOrgCache removes a cached organization. Call after any write.
func EvictOrgCache(owner, name string) {
	orgCache.delete(orgCacheKey(owner, name))
}

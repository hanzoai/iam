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

package conf

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Brand is the on-disk contract IAM reads from /etc/brand/brand.json
// (mounted from a ConfigMap by the deployment). It carries the per-env
// branding inputs that IAM needs to behave brand-neutrally — domain
// allow-lists for auto-promotion, primary brand domain, etc.
//
// This file MUST live in /etc/brand/brand.json or wherever IAM_BRAND_FILE
// points. If neither exists, fallback defaults apply (defaultBrand).
//
// JSON shape (intentionally small; add fields incrementally):
//
//	{
//	  "name": "Hanzo",
//	  "domain": "hanzo.ai",
//	  "superadminDomains": [
//	    { "domain": "hanzo.ai",    "org": "admin", "globalAdmin": true  },
//	    { "domain": "zoo.ngo",     "org": "admin", "globalAdmin": true  },
//	    { "domain": "lux.network", "org": "admin", "globalAdmin": true  },
//	    { "domain": "pars.network","org": "pars",  "globalAdmin": false }
//	  ]
//	}
//
// The "org" sentinel value "admin" (literal string) is treated as
// "resolve to the live AdminOrg at call time" — see brand.ResolveOrg.
type Brand struct {
	Name              string                 `json:"name"`
	Domain            string                 `json:"domain"`
	SuperadminDomains []SuperadminDomainRule `json:"superadminDomains"`
}

// SuperadminDomainRule maps one email domain to a promotion outcome.
// Org="admin" is a sentinel — resolved against the live AdminOrg.
// Org="<orgName>" means "user is moved into that org but does not get
// global admin (unless GlobalAdmin is also true)".
type SuperadminDomainRule struct {
	Domain      string `json:"domain"`
	Org         string `json:"org"`
	GlobalAdmin bool   `json:"globalAdmin"`
}

// defaultBrand is the fallback shipped for hanzo-flavored deployments.
// White-label users override by mounting their own /etc/brand/brand.json.
//
// SECURITY: SuperadminDomains is INTENTIONALLY EMPTY in the default.
// Auto-promoting `@hanzo.ai` / `@zoo.ngo` / `@lux.network` to global admin
// is appropriate for Hanzo's OWN deployment (operators run `hanzo iam
// init` which writes the populated brand.json) but DANGEROUS as a fallback
// — a white-label tenant (Liquidity, etc.) with a broken ConfigMap mount
// would hand global admin to the wrong domains. The default must be
// fail-safe (zero auto-promotion); operators populate explicitly.
var defaultBrand = Brand{
	Name:              "Hanzo",
	Domain:            "hanzo.ai",
	SuperadminDomains: []SuperadminDomainRule{},
}

var (
	brandOnce sync.Once
	brandMu   sync.RWMutex
	brand     Brand
	brandErr  error
)

// BrandFilePath returns the path IAM reads the brand contract from.
// Env var IAM_BRAND_FILE overrides the default.
func BrandFilePath() string {
	if p := os.Getenv("IAM_BRAND_FILE"); p != "" {
		return p
	}
	return "/etc/brand/brand.json"
}

// LoadBrand reads /etc/brand/brand.json (or IAM_BRAND_FILE). On any error
// (including file-not-found) returns the defaultBrand and the error;
// callers should fall back to the default but may want to log the error.
//
// Safe to call concurrently; lazy: the file is read once and cached.
func LoadBrand() (Brand, error) {
	brandOnce.Do(func() {
		path := BrandFilePath()
		buf, err := os.ReadFile(path)
		if err != nil {
			brandErr = fmt.Errorf("brand: %w (using defaults)", err)
			brandMu.Lock()
			brand = defaultBrand
			brandMu.Unlock()
			return
		}
		var b Brand
		if err := json.Unmarshal(buf, &b); err != nil {
			brandErr = fmt.Errorf("brand: parse %s: %w (using defaults)", path, err)
			brandMu.Lock()
			brand = defaultBrand
			brandMu.Unlock()
			return
		}
		// Nil superadminDomains is treated as an empty list (no auto-promotion).
		// This is intentional fail-safe behavior — a brand.json that omits the
		// field gets no auto-promotion, NOT the (now-empty) defaults.
		if b.SuperadminDomains == nil {
			b.SuperadminDomains = []SuperadminDomainRule{}
		}
		brandMu.Lock()
		brand = b
		brandMu.Unlock()
	})
	brandMu.RLock()
	out := brand
	brandMu.RUnlock()
	return out, brandErr
}

// ReloadBrand invalidates the cached brand for tests. Not safe for
// concurrent use with LoadBrand outside tests — production reads the
// file once at startup.
func ReloadBrand() {
	brandMu.Lock()
	brandOnce = sync.Once{}
	brand = Brand{}
	brandErr = nil
	brandMu.Unlock()
}

// SuperadminRuleFor returns the rule matching the given email domain.
// Case-insensitive on the domain match. The returned rule has its Org
// resolved against the live AdminOrg (so "admin" sentinel becomes
// AdminOrg from env).
func SuperadminRuleFor(email string) (SuperadminDomainRule, bool) {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return SuperadminDomainRule{}, false
	}
	domain := strings.ToLower(email[at+1:])
	b, _ := LoadBrand()
	for _, r := range b.SuperadminDomains {
		if strings.EqualFold(r.Domain, domain) {
			// Resolve "admin" sentinel against the live AdminOrg.
			if r.Org == "admin" || (r.GlobalAdmin && r.Org == "") {
				r.Org = AdminOrg
			}
			return r, true
		}
	}
	return SuperadminDomainRule{}, false
}

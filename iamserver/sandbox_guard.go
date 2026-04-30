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

package iamserver

import (
	"net/url"
	"os"
	"strings"

	"github.com/beego/beego/v2/core/logs"
	"github.com/hanzoai/iam/conf"
)

// sandboxOriginAllowlist returns hostname suffixes / exact values that are
// allowed to run with SANDBOX_GLOBAL_OTP enabled. Anything else triggers a
// hard fail at boot. Suffixes start with ".", exact matches do not.
var sandboxOriginAllowlist = []string{
	".dev.",
	".test.",
	".local",
	"localhost",
	"127.0.0.1",
	"0.0.0.0",
	"::1",
}

// hostMatchesSandboxAllowlist returns true if host is acceptable for sandbox
// bypass. Comparison is case-insensitive on the hostname part only (port
// stripped).
func hostMatchesSandboxAllowlist(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// Strip port if present.
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	// Strip surrounding brackets from IPv6 literal.
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	for _, allowed := range sandboxOriginAllowlist {
		if strings.HasPrefix(allowed, ".") {
			if strings.HasSuffix(host, allowed) {
				return true
			}
			// Allow bare apex matching the suffix root (e.g. "dev.").
			if host == strings.TrimPrefix(allowed, ".") {
				return true
			}
		} else if host == allowed {
			return true
		}
	}
	return false
}

// extractHost pulls the hostname from a value that may be a bare host or a
// full URL. Returns "" if nothing usable is in s.
func extractHost(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return s
}

// resolveOrigin returns the origin/host the operator configured for this
// IAM. It checks ORIGIN env first, then beego app.conf "origin", then
// falls back to "" (which fails the allowlist and panics).
func resolveOrigin() string {
	if v := strings.TrimSpace(os.Getenv("ORIGIN")); v != "" {
		return v
	}
	return strings.TrimSpace(conf.GetConfigString("origin"))
}

// EnforceSandboxOriginGuard runs at boot. If SANDBOX_GLOBAL_OTP is set, the
// configured origin MUST be on the sandbox allowlist or IAM panics. This
// prevents copy-paste of devnet manifests to mainnet from silently
// disabling MFA across every account. See finding A in red review
// 2026-04-30.
func EnforceSandboxOriginGuard() {
	pinned := strings.TrimSpace(os.Getenv("SANDBOX_GLOBAL_OTP"))
	if pinned == "" {
		return
	}

	originRaw := resolveOrigin()
	host := extractHost(originRaw)

	if !hostMatchesSandboxAllowlist(host) {
		// Hard fail. Refuse to boot. Operator must either remove
		// SANDBOX_GLOBAL_OTP from the manifest or fix ORIGIN to point at
		// a real sandbox host.
		panic("SANDBOX_GLOBAL_OTP is set but ORIGIN/origin (" + originRaw +
			") is not on the sandbox allowlist (.dev., " +
			".test., .local, localhost, 127.0.0.1). Refusing " +
			"to boot — this would silently bypass MFA for every account.")
	}

	logs.Info("[sandbox-guard] SANDBOX_GLOBAL_OTP active for origin=%s — verification bypass enabled. This MUST NOT be set in production manifests.", host)
}

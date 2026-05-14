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

package object

import (
	"reflect"
	"testing"
)

func TestSplitOriginList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "https://hanzo.id", []string{"https://hanzo.id"}},
		{"two", "https://hanzo.id,https://lux.id", []string{"https://hanzo.id", "https://lux.id"}},
		{
			"production-prod-config",
			"https://hanzo.ai,https://hanzo.id,https://lux.id,https://zoo.id,https://pars.id,https://id.ad.nexus,https://id.bootno.de,https://id.hanzo.ai,https://id.lux.network,https://id.zoo.network,https://id.pars.network,https://iam.hanzo.ai,https://auth.hanzo.ai,https://auth.zoo.ngo,https://auth.pars.ai",
			[]string{
				"https://hanzo.ai",
				"https://hanzo.id",
				"https://lux.id",
				"https://zoo.id",
				"https://pars.id",
				"https://id.ad.nexus",
				"https://id.bootno.de",
				"https://id.hanzo.ai",
				"https://id.lux.network",
				"https://id.zoo.network",
				"https://id.pars.network",
				"https://iam.hanzo.ai",
				"https://auth.hanzo.ai",
				"https://auth.zoo.ngo",
				"https://auth.pars.ai",
			},
		},
		{"trim-spaces", "  https://a  ,  https://b  ", []string{"https://a", "https://b"}},
		{"drop-empty", "https://a,,https://b,", []string{"https://a", "https://b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitOriginList(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("SplitOriginList(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSelectOriginForHost(t *testing.T) {
	prod := []string{
		"https://hanzo.ai",
		"https://hanzo.id",
		"https://lux.id",
		"https://zoo.id",
		"https://pars.id",
		"https://iam.hanzo.ai",
	}
	tests := []struct {
		name string
		list []string
		host string
		want string
	}{
		{"empty-list", nil, "hanzo.id", ""},
		{"exact-match", prod, "hanzo.id", "https://hanzo.id"},
		{"lux", prod, "lux.id", "https://lux.id"},
		{"zoo", prod, "zoo.id", "https://zoo.id"},
		{"pars", prod, "pars.id", "https://pars.id"},
		{"strip-port-from-host", prod, "hanzo.id:443", "https://hanzo.id"},
		{"case-insensitive", prod, "Hanzo.ID", "https://hanzo.id"},
		{"iam-domain", prod, "iam.hanzo.ai", "https://iam.hanzo.ai"},
		// No match — fall back to first entry. This is acceptable: the
		// caller is hitting a host the operator didn't put in `origin`.
		// Single-tenant deployments rely on this fallback.
		{"no-match-fallback", prod, "unknown.example", "https://hanzo.ai"},
		// Origin with explicit port: hostname comparison only.
		{"origin-with-port", []string{"http://localhost:7001"}, "localhost", "http://localhost:7001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectOriginForHost(tt.list, tt.host)
			if got != tt.want {
				t.Fatalf("selectOriginForHost(%v, %q) = %q, want %q", tt.list, tt.host, got, tt.want)
			}
		})
	}
}

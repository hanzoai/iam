// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server_test

import (
	"testing"

	"github.com/hanzoai/iam/server"
)

// The boot check refuses every issuer config it cannot mint under, and nothing
// stands in for the refused value.
func TestRequireIssuer(t *testing.T) {
	boot := func(t *testing.T, issuer, issuerMap, signinMap string) error {
		t.Helper()
		t.Setenv("IAM_ISSUER", issuer)
		t.Setenv("IAM_ISSUER_MAP", issuerMap)
		t.Setenv("IAM_FEDERATION_ORIGIN_MAP", signinMap)
		t.Setenv("IAM_DEV_HOST_RELATIVE", "")
		return server.RequireIssuer()
	}
	for _, tc := range []struct{ name, issuer, issuerMap, signinMap string }{
		{name: "empty IAM_ISSUER", issuer: ""},
		{name: "whitespace IAM_ISSUER", issuer: "   "},
		{name: "http IAM_ISSUER", issuer: "http://hanzo.id"},
		{name: "scheme-less IAM_ISSUER", issuer: "hanzo.id"},
		{name: "IAM_ISSUER_MAP that is not JSON", issuer: "https://hanzo.id", issuerMap: `{not json}`},
		{name: "IAM_ISSUER_MAP naming an http issuer", issuer: "https://hanzo.id", issuerMap: `{"lux.id":"http://lux.id"}`},
		{name: "IAM_ISSUER_MAP with an empty host", issuer: "https://hanzo.id", issuerMap: `{"":"https://lux.id"}`},
		{name: "IAM_ISSUER_MAP without IAM_ISSUER", issuer: "", issuerMap: `{"lux.id":"https://lux.id"}`},
		{name: "a sign-in map that is not JSON", issuer: "https://hanzo.id", signinMap: `{not json}`},
		{name: "a sign-in origin in another brand", issuer: "https://hanzo.id",
			issuerMap: `{"lux.id":"https://lux.id"}`, signinMap: `{"hanzo.id":"https://lux.id"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := boot(t, tc.issuer, tc.issuerMap, tc.signinMap); err == nil {
				t.Fatalf("RequireIssuer booted on IAM_ISSUER=%q IAM_ISSUER_MAP=%q IAM_FEDERATION_ORIGIN_MAP=%q",
					tc.issuer, tc.issuerMap, tc.signinMap)
			}
		})
	}
	t.Run("a pinned https issuer boots", func(t *testing.T) {
		if err := boot(t, "https://hanzo.id", `{"lux.id":"https://lux.id"}`, `{"hanzo.ai":"https://hanzo.ai"}`); err != nil {
			t.Fatalf("RequireIssuer: %v", err)
		}
	})
}

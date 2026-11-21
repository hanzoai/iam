// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/iam/internal/keyring"
)

// bootWith runs InitIssuerResolver under the given environment and restores the
// process's resolver and environment after the test.
func bootWith(t *testing.T, issuer, issuerMap, tenant, accepted string) error {
	t.Helper()
	keys := []string{"IAM_ISSUER", "IAM_ISSUER_MAP", EnvTenantIssuer, EnvAcceptedIssuers}
	prev := map[string]*string{}
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			v := v
			prev[k] = &v
		} else {
			prev[k] = nil
		}
	}
	prevResolver, prevBase := activeResolver.Load(), activeTenantBase.Load()
	t.Cleanup(func() {
		for k, v := range prev {
			if v == nil {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, *v)
			}
		}
		activeResolver.Store(prevResolver)
		activeTenantBase.Store(prevBase)
	})
	for k, v := range map[string]string{"IAM_ISSUER": issuer, "IAM_ISSUER_MAP": issuerMap, EnvTenantIssuer: tenant, EnvAcceptedIssuers: accepted} {
		if v == "" {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, v)
		}
	}
	return InitIssuerResolver()
}

// The set is an https origin list, normalized, and refuses anything that is not an origin.
func TestAcceptedIssuers_AreHTTPSOrigins(t *testing.T) {
	for name, c := range map[string]struct {
		raw  string
		want []string
		bad  bool
	}{
		"none":               {raw: ""},
		"blank entries":      {raw: " , ,", want: nil},
		"two":                {raw: "https://hanzo.id, https://hanzo.ai", want: []string{"https://hanzo.ai", "https://hanzo.id"}},
		"normalized":         {raw: "https://Hanzo.AI/,https://hanzo.ai:443,https://hanzo.ai", want: []string{"https://hanzo.ai"}},
		"http":               {raw: "http://hanzo.id", bad: true},
		"a path":             {raw: "https://hanzo.ai/acme", bad: true},
		"a query":            {raw: "https://hanzo.ai?x=1", bad: true},
		"a user":             {raw: "https://u@hanzo.ai", bad: true},
		"an ip":              {raw: "https://10.0.0.1", bad: true},
		"scheme-less":        {raw: "hanzo.ai", bad: true},
		"one bad of several": {raw: "https://hanzo.id,hanzo.ai", bad: true},
	} {
		got, err := newAcceptedIssuers(c.raw)
		if c.bad {
			if err == nil {
				t.Errorf("%s: %q accepted: %v", name, c.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		list := acceptedList(got)
		if len(list) != len(c.want) {
			t.Errorf("%s: got %v, want %v", name, list, c.want)
			continue
		}
		for _, w := range c.want {
			if !got[w] {
				t.Errorf("%s: %s missing from %v", name, w, list)
			}
		}
	}
}

// The tenant origin may itself be a platform issuer, because an organization's issuer
// always has an org after it; a platform issuer UNDER the origin is still refused.
func TestAcceptedIssuers_BootAgainstTheTenantOrigin(t *testing.T) {
	for name, c := range map[string]struct {
		issuer, m, tenant, accepted string
		boots                       bool
	}{
		"disjoint":                          {"https://hanzo.id", "", "https://hanzo.ai", "", true},
		"accepted is the tenant origin":     {"https://hanzo.id", "", "https://hanzo.ai", "https://hanzo.id,https://hanzo.ai", true},
		"default is the tenant origin":      {"https://hanzo.ai", "", "https://hanzo.ai", "https://hanzo.id", true},
		"a brand issuer is it":              {"https://hanzo.id", `{"hanzo.ai":"https://hanzo.ai"}`, "https://hanzo.ai", "https://hanzo.id", true},
		"default lies under it":             {"https://hanzo.ai/x", "", "https://hanzo.ai", "", false},
		"a brand issuer lies under it":      {"https://hanzo.id", `{"lux.id":"https://hanzo.ai/lux"}`, "https://hanzo.ai", "", false},
		"accepted with a path is no origin": {"https://hanzo.id", "", "https://hanzo.ai", "https://hanzo.ai/acme", false},
		"accepted is malformed":             {"https://hanzo.id", "", "https://hanzo.ai", "hanzo.ai", false},
	} {
		err := bootWith(t, c.issuer, c.m, c.tenant, c.accepted)
		if c.boots && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if !c.boots && err == nil {
			t.Errorf("%s: booted", name)
		}
	}
}

// Accepting an issuer is verification and nothing else: it is not one IAM mints under or
// advertises, and an organization's issuer is never accepted through it.
func TestAcceptedIssuers_VerifyOnly(t *testing.T) {
	if err := bootWith(t, "https://hanzo.id", `{"hanzo.ai":"https://hanzo.id"}`, "https://hanzo.ai", "https://hanzo.ai"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		iss                          string
		mints, accepts, acceptedOnly bool
	}{
		{"https://hanzo.id", true, true, false},
		{"https://hanzo.id/", true, true, false},
		{"https://hanzo.ai", false, true, true},
		{"https://hanzo.ai/", false, true, true},
		{"https://hanzo.ai/acme", false, false, false}, // an organization's issuer, never through the set
		{"https://hanzo.ai.evil.example", false, false, false},
		{"https://lux.id", false, false, false},
		{"", false, false, false},
	} {
		if got := issues(c.iss); got != c.mints {
			t.Errorf("issues(%q) = %v, want %v", c.iss, got, c.mints)
		}
		if got := accepts(c.iss); got != c.accepts {
			t.Errorf("accepts(%q) = %v, want %v", c.iss, got, c.accepts)
		}
		if got := acceptedOnly(c.iss); got != c.acceptedOnly {
			t.Errorf("acceptedOnly(%q) = %v, want %v", c.iss, got, c.acceptedOnly)
		}
	}
	// A host never resolves to an accepted-only issuer, so nothing mints under one.
	for _, host := range []string{"hanzo.ai", "hanzo.id", "unknown.example", ""} {
		if iss, err := resolveIssuer(host); err != nil || iss != "https://hanzo.id" {
			t.Errorf("resolveIssuer(%q) = %q, %v: minted under an accepted-only issuer", host, iss, err)
		}
	}
	// Mutation check: with the set empty, the same token is refused.
	if err := bootWith(t, "https://hanzo.id", "", "https://hanzo.ai", ""); err != nil {
		t.Fatal(err)
	}
	if accepts("https://hanzo.ai") {
		t.Error("an issuer was accepted with IAM_ACCEPTED_ISSUERS unset")
	}
}

// A platform-signed access token under an accepted issuer verifies as a bearer; the same
// token under any other issuer does not; and a token under an organization's issuer never
// does, whatever the set holds.
func TestAcceptedIssuers_AnAccessTokenUnderThemVerifies(t *testing.T) {
	_, db := newServer(t)
	app := seedApp(t, db, appOpts{clientID: "hanzo-console"})
	ctx := context.Background()
	now := time.Now()
	mint := func(iss string) string {
		t.Helper()
		signer, err := signerFor(ctx, db, app, iss)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := signer.Sign(app, Identity{Id: "u1"}, "openid", "", time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if err := bootWith(t, "https://hanzo.id", "", "https://hanzo.ai", "https://hanzo.ai"); err != nil {
		t.Fatal(err)
	}
	for iss, want := range map[string]bool{
		"https://hanzo.id":      true,
		"https://hanzo.ai":      true,
		"https://lux.id":        false,
		"https://hanzo.ai/acme": false,
	} {
		_, err := verifyBearer(ctx, db, mint(iss))
		if (err == nil) != want {
			t.Errorf("verifyBearer under %s: err=%v, want ok=%v", iss, err, want)
		}
	}
	// Mutation check: the set is what lets the hanzo.ai token through.
	if err := bootWith(t, "https://hanzo.id", "", "https://hanzo.ai", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBearer(ctx, db, mint("https://hanzo.ai")); err == nil {
		t.Error("a token under hanzo.ai verified with no accepted issuers")
	}
}

// A credential that replaces one under an accepted-only issuer is minted under the
// default issuer; one under a minted issuer keeps it.
func TestAcceptedIssuers_AReplacementIsMintedUnderTheDefault(t *testing.T) {
	if err := bootWith(t, "https://hanzo.id", "", "https://hanzo.ai", "https://hanzo.ai"); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"https://hanzo.ai": "https://hanzo.id",
		"https://hanzo.id": "https://hanzo.id",
	} {
		if got, err := reissuer(in); err != nil || got != want {
			t.Errorf("reissuer(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
}

// An agent's assertion lives days. One minted under the issuer being moved from still
// verifies under the new one, one under an unlisted issuer does not, and the audience must
// be the issuer it names.
func TestAcceptedIssuers_AnAgentAssertionUnderThemVerifies(t *testing.T) {
	_, db := newServer(t)
	agent := seedApp(t, db, appOpts{clientID: "hanzo-agent"})
	ctx := context.Background()
	now := time.Now()
	reg := agentRegPrefix + strings.Repeat("a", 26)
	mint := func(iss string) string {
		t.Helper()
		a, _, err := agentAssertionFor(ctx, db, agent, reg, iss, now)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	// IAM mints under hanzo.ai after the flip; hanzo.id is the accepted one.
	if err := bootWith(t, "https://hanzo.ai", "", "https://hanzo.ai", "https://hanzo.id"); err != nil {
		t.Fatal(err)
	}
	for iss, want := range map[string]bool{
		"https://hanzo.ai": true,
		"https://hanzo.id": true,
		"https://lux.id":   false,
	} {
		_, err := verifyAgentAssertion(ctx, db, mint(iss), "https://hanzo.ai")
		if (err == nil) != want {
			t.Errorf("assertion under %s: err=%v, want ok=%v", iss, err, want)
		}
	}
	if !assertionIssuer("https://hanzo.id", "https://hanzo.ai") || assertionIssuer("https://lux.id", "https://hanzo.ai") {
		t.Error("assertionIssuer does not read the accepted set")
	}
	// Mutation check: with the set empty, the old issuer's assertion is refused.
	if err := bootWith(t, "https://hanzo.ai", "", "https://hanzo.ai", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAgentAssertion(ctx, db, mint("https://hanzo.id"), "https://hanzo.ai"); err == nil {
		t.Error("an assertion under hanzo.id verified with no accepted issuers")
	}
}

// A projected ServiceAccount token names the issuer as its audience. While the issuer moves
// a pod may hold either: the one asked of and every accepted one verify; nothing else does.
func TestAcceptedIssuers_WorkloadAudiences(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo:pkg": "hanzo"})
	app, db := newServer(t)
	serviceApp(t, db, "hanzo-pkg")
	sa := "system:serviceaccount:hanzo:pkg"
	present := func(aud string) int {
		status, _ := present(t, app, c.assertion(t, "cluster-key-1", sa, aud, time.Hour), nil)
		return status
	}
	if err := bootWith(t, "https://hanzo.id", "", "https://hanzo.ai", "https://hanzo.ai"); err != nil {
		t.Fatal(err)
	}
	for aud, want := range map[string]int{
		"https://hanzo.id":       200,
		"https://hanzo.ai":       200,
		"https://vault.internal": 400,
		"https://hanzo.ai/acme":  400,
	} {
		if got := present(aud); got != want {
			t.Errorf("audience %s: status %d, want %d", aud, got, want)
		}
	}
	// Mutation check: the set is what lets the second audience through.
	if err := bootWith(t, "https://hanzo.id", "", "https://hanzo.ai", ""); err != nil {
		t.Fatal(err)
	}
	if got := present("https://hanzo.ai"); got != 400 {
		t.Errorf("audience hanzo.ai with no accepted issuers: status %d, want 400", got)
	}
}

// With IAM_ISSUER_MAP naming hanzo.ai, the platform discovery document and key set answer
// on that host under https://hanzo.ai while an organization's documents keep answering at
// `/<org>/.well-known/*`, and an accepted-only issuer is never advertised.
func TestAcceptedIssuers_PlatformDiscoveryOnTheNewHost(t *testing.T) {
	app, db := newServer(t)
	seedRSACert(t, db, "cert-hanzo")
	keyring.Set("cert-hanzo", rsaKeyToPEM(t, sharedKey(t)))
	if err := bootWith(t, "https://hanzo.id", `{"hanzo.ai":"https://hanzo.ai","www.hanzo.ai":"https://hanzo.ai"}`, "https://hanzo.ai", "https://hanzo.id"); err != nil {
		t.Fatal(err)
	}
	get := func(host, path string) (int, map[string]any, string) {
		req := formReqNoBody("GET", path)
		req.Host = host
		resp, body := do(t, app, req)
		var d map[string]any
		if strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
			d = decode(t, body)
		}
		return resp.StatusCode, d, string(body)
	}
	for _, path := range []string{PathDiscovery, PathDiscoveryV1, PathASMetadata, PathASMetadataV1} {
		code, d, _ := get("hanzo.ai", path)
		if code != 200 || d["issuer"] != "https://hanzo.ai" || d["jwks_uri"] != "https://hanzo.ai"+PathJWKS {
			t.Errorf("hanzo.ai %s: %d issuer=%v jwks_uri=%v", path, code, d["issuer"], d["jwks_uri"])
		}
	}
	// The unmapped host keeps its own issuer, and an accepted-only one is advertised nowhere.
	code, d, raw := get("hanzo.id", PathDiscovery)
	if code != 200 || d["issuer"] != "https://hanzo.id" {
		t.Errorf("hanzo.id: %d issuer=%v", code, d["issuer"])
	}
	if strings.Contains(raw, "accepted") {
		t.Errorf("discovery mentions the accepted set: %s", raw)
	}
	for _, path := range []string{PathJWKSRoot, PathJWKS} {
		code, d, _ := get("hanzo.ai", path)
		keys, _ := d["keys"].([]any)
		if code != 200 || len(keys) == 0 {
			t.Errorf("hanzo.ai %s: %d with %d keys", path, code, len(keys))
		}
	}
	// An organization's documents are its own: a platform host never answers them for an
	// organization with no tenant cert, and `/.well-known/*` never answers as one.
	if code, _, _ := get("hanzo.ai", "/acme"+PathDiscovery); code != 404 {
		t.Errorf("/acme discovery with no tenant cert: %d, want 404", code)
	}
}

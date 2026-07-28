// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The hanzo-cli login, end to end, exactly as the CLI performs it
// (hanzo/cli src/iam/oauth.rs): bind an EPHEMERAL loopback port, authorize with
// PKCE S256 against the portless registration the provisioner writes for a `cli`
// app, then exchange the code presenting NO client secret.
//
// Every step below failed before the RFC 8252 §7.3 fix: authorize answered 400
// "invalid redirect_uri" because the registration is http://127.0.0.1/callback
// and the CLI necessarily sends http://127.0.0.1:<ephemeral>/callback. The
// browser never returned, so the CLI blocked on accept() forever — the reported
// "loopback flow hangs" symptom.
const cliRegisteredRedirect = "http://127.0.0.1/callback"

// runtimeRedirect is what the CLI builds after binding 127.0.0.1:0.
const runtimeRedirect = "http://127.0.0.1:51234/callback"

func TestCLILoopbackPKCEFlow_EndToEnd(t *testing.T) {
	app, db := newServer(t)
	// A `cli` app as provisioned: public (no secret), portless loopback
	// registration, authorization_code + refresh_token.
	seedApp(t, db, appOpts{
		clientID:     "hanzo-cli",
		secret:       "", // public client
		redirectURIs: []string{cliRegisteredRedirect, "http://localhost/callback"},
		refreshHours: 24,
		grants:       []string{"authorization_code", "refresh_token"},
	})
	seedUser(t, db, "z", "z@hanzo.ai", "IloveHanzo2026!!")

	verifier := "KmKyPMK1T4JxydUiDsLmCaz79cqcmYqoBCpaeWWoxrU"
	challenge := ComputeS256Challenge(verifier)

	// 1. authorize — the ephemeral port must be accepted.
	q := url.Values{
		"client_id":             {"hanzo-cli"},
		"response_type":         {"code"},
		"redirect_uri":          {runtimeRedirect},
		"scope":                 {"openid profile email"},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp, body := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+q.Encode()))
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "redirect_uri") {
		t.Fatalf("authorize rejected the ephemeral loopback port — this is the hang: %s", body)
	}
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize: status %d body %s", resp.StatusCode, body)
	}

	// 2. login for a code bound to that same runtime redirect_uri.
	code, resp, body := loginForCode(t, app, map[string]string{
		"application":   "hanzo-cli",
		"organization":  "hanzo",
		"username":      "z",
		"password":      "IloveHanzo2026!!",
		"clientId":      "hanzo-cli",
		"redirectUri":   runtimeRedirect,
		"codeChallenge": challenge,
		"scope":         "openid profile email",
	})
	if code == "" {
		t.Fatalf("login produced no code: status %d body %s", resp.StatusCode, body)
	}

	// 3. token exchange with the verifier and NO client secret.
	resp, tok := exchangeCode(t, app, url.Values{
		"client_id":     {"hanzo-cli"},
		"code":          {code},
		"redirect_uri":  {runtimeRedirect},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: status %d body %v", resp.StatusCode, tok)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("token endpoint content-type = %q, want JSON (never an HTML SPA shell)", ct)
	}
	for _, k := range []string{"access_token", "id_token", "refresh_token", "token_type"} {
		if v, _ := tok[k].(string); v == "" {
			t.Errorf("token response missing %s: %v", k, tok)
		}
	}
}

// The port wildcard must not become a way to skip PKCE. A public client with no
// challenge is still refused, so the relaxed matching widens the redirect only.
func TestCLILoopback_StillRequiresPKCE(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{
		clientID:     "hanzo-cli",
		secret:       "",
		redirectURIs: []string{cliRegisteredRedirect},
		grants:       []string{"authorization_code"},
	})
	seedUser(t, db, "z", "z@hanzo.ai", "IloveHanzo2026!!")

	// A public client that omits the challenge is refused at MINT time — the
	// code never exists, so there is nothing to exchange.
	code, _, body := loginForCode(t, app, map[string]string{
		"application":  "hanzo-cli",
		"organization": "hanzo",
		"username":     "z",
		"password":     "IloveHanzo2026!!",
		"clientId":     "hanzo-cli",
		"redirectUri":  runtimeRedirect,
		// no codeChallenge
	})
	if code != "" {
		t.Fatalf("public client minted a code with no PKCE challenge: %s", body)
	}
	if !strings.Contains(string(body), "PKCE is required for public clients") {
		t.Fatalf("expected the public-client PKCE refusal, got: %s", body)
	}
}

// The authorization code stays bound to the EXACT redirect_uri it was minted
// for. Port-agnostic REGISTRATION must not turn into port-agnostic REDEMPTION.
func TestCLILoopback_CodeBoundToExactPort(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{
		clientID:     "hanzo-cli",
		secret:       "",
		redirectURIs: []string{cliRegisteredRedirect},
		grants:       []string{"authorization_code"},
	})
	seedUser(t, db, "z", "z@hanzo.ai", "IloveHanzo2026!!")

	verifier := "KmKyPMK1T4JxydUiDsLmCaz79cqcmYqoBCpaeWWoxrU"
	code, _, _ := loginForCode(t, app, map[string]string{
		"application":   "hanzo-cli",
		"organization":  "hanzo",
		"username":      "z",
		"password":      "IloveHanzo2026!!",
		"clientId":      "hanzo-cli",
		"redirectUri":   runtimeRedirect,
		"codeChallenge": ComputeS256Challenge(verifier),
	})
	if code == "" {
		t.Fatal("no code minted")
	}
	// Same client, same registration, DIFFERENT port than the code was bound to.
	resp, tok := exchangeCode(t, app, url.Values{
		"client_id":     {"hanzo-cli"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"code_verifier": {verifier},
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("code redeemed against a port it was not bound to: %v", tok)
	}
}

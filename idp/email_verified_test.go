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

// email_verified_test.go — each provider must surface its verified-email signal
// into UserInfo.EmailVerified (Red HIGH-2). The account-linking gate
// (object.MayLinkByVerifiedEmail) relies on this flag being TRUE only when the
// provider actually verified the address.

package idp

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// cannedResp is a fixed HTTP reply keyed by request path.
type cannedResp struct {
	status int
	body   string
}

type cannedRT struct{ byPath map[string]cannedResp }

func (c *cannedRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r, ok := c.byPath[req.URL.Path]
	if !ok {
		r = cannedResp{status: http.StatusNotFound, body: "{}"}
	}
	return &http.Response{
		StatusCode: r.status,
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Header:     make(http.Header),
	}, nil
}

func cannedClient(routes map[string]cannedResp) *http.Client {
	return &http.Client{Transport: &cannedRT{byPath: routes}}
}

// --- Google -----------------------------------------------------------------

func TestGoogle_OneTap_EmailVerified(t *testing.T) {
	p := NewGoogleIdProvider("cid", "csec", "https://cb")
	mk := func(v string) *oauth2.Token {
		return (&oauth2.Token{AccessToken: GoogleIdTokenKey + "-sub"}).WithExtra(map[string]interface{}{
			GoogleIdTokenKey: GoogleIdToken{Sub: "sub", Email: "u@gmail.com", EmailVerified: v, Name: "U"},
		})
	}
	if ui, err := p.GetUserInfo(mk("true")); err != nil || !ui.EmailVerified {
		t.Fatalf("OneTap verified: err=%v EmailVerified=%v (want true)", err, ui.EmailVerified)
	}
	if ui, err := p.GetUserInfo(mk("false")); err != nil || ui.EmailVerified {
		t.Fatalf("OneTap unverified must be false: err=%v EmailVerified=%v", err, ui.EmailVerified)
	}
}

func TestGoogle_Api_EmailVerified(t *testing.T) {
	p := NewGoogleIdProvider("cid", "csec", "https://cb")
	tok := &oauth2.Token{AccessToken: "at"}

	p.SetHttpClient(cannedClient(map[string]cannedResp{
		"/oauth2/v2/userinfo": {200, `{"id":"1","email":"u@gmail.com","verified_email":true,"name":"U"}`},
		"/v1/people/me":       {200, `{}`},
	}))
	if ui, err := p.GetUserInfo(tok); err != nil || !ui.EmailVerified {
		t.Fatalf("api verified_email=true: err=%v EmailVerified=%v (want true)", err, ui.EmailVerified)
	}

	p.SetHttpClient(cannedClient(map[string]cannedResp{
		"/oauth2/v2/userinfo": {200, `{"id":"1","email":"u@gmail.com","verified_email":false,"name":"U"}`},
		"/v1/people/me":       {200, `{}`},
	}))
	if ui, err := p.GetUserInfo(tok); err != nil || ui.EmailVerified {
		t.Fatalf("api verified_email=false must be false: err=%v EmailVerified=%v", err, ui.EmailVerified)
	}
}

// --- GitHub -----------------------------------------------------------------

func TestGitHub_EmailVerified_ProfileEmail(t *testing.T) {
	p := NewGithubIdProvider("cid", "csec", "https://cb")
	p.SetHttpClient(cannedClient(map[string]cannedResp{
		"/user": {200, `{"id":42,"login":"octo","name":"Octo","email":"octo@corp.example","avatar_url":"http://a"}`},
	}))
	ui, err := p.GetUserInfo(&oauth2.Token{AccessToken: "t"})
	if err != nil || ui.Email != "octo@corp.example" || !ui.EmailVerified {
		t.Fatalf("public profile email is GitHub-verified: err=%v email=%q verified=%v", err, ui.Email, ui.EmailVerified)
	}
}

func TestGitHub_EmailVerified_FromEmailsEndpoint(t *testing.T) {
	p := NewGithubIdProvider("cid", "csec", "https://cb")
	p.SetHttpClient(cannedClient(map[string]cannedResp{
		"/user":        {200, `{"id":42,"login":"octo","name":"Octo","avatar_url":"http://a"}`},
		"/user/emails": {200, `[{"email":"real@corp.example","primary":true,"verified":true}]`},
	}))
	ui, err := p.GetUserInfo(&oauth2.Token{AccessToken: "t"})
	if err != nil || ui.Email != "real@corp.example" || !ui.EmailVerified {
		t.Fatalf("verified email from /user/emails: err=%v email=%q verified=%v", err, ui.Email, ui.EmailVerified)
	}
}

func TestGitHub_EmailVerified_UnverifiedInListYieldsNothing(t *testing.T) {
	p := NewGithubIdProvider("cid", "csec", "https://cb")
	p.SetHttpClient(cannedClient(map[string]cannedResp{
		"/user":        {200, `{"id":42,"login":"octo","name":"Octo"}`},
		"/user/emails": {200, `[{"email":"unv@corp.example","primary":true,"verified":false}]`},
	}))
	ui, err := p.GetUserInfo(&oauth2.Token{AccessToken: "t"})
	if err != nil || ui.Email != "" || ui.EmailVerified {
		t.Fatalf("an unverified-only list must yield empty+unverified: err=%v email=%q verified=%v", err, ui.Email, ui.EmailVerified)
	}
}

func TestGitHub_EmailVerified_NoreplyFallbackIsTrusted(t *testing.T) {
	p := NewGithubIdProvider("cid", "csec", "https://cb")
	p.SetHttpClient(cannedClient(map[string]cannedResp{
		"/user":        {200, `{"id":42,"login":"octo","name":"Octo"}`},
		"/user/emails": {403, `{"message":"Resource not accessible by integration"}`},
	}))
	ui, err := p.GetUserInfo(&oauth2.Token{AccessToken: "t"})
	want := "42+octo@users.noreply.github.com"
	if err != nil || ui.Email != want || !ui.EmailVerified {
		t.Fatalf("GitHub-issued noreply is a trusted identity: err=%v email=%q (want %q) verified=%v", err, ui.Email, want, ui.EmailVerified)
	}
}

func TestGitHub_getEmailFromEmailsResult(t *testing.T) {
	p := &GithubIdProvider{}
	if e, v := p.getEmailFromEmailsResult([]GitHubUserEmailInfo{{Email: "p@x", Primary: true, Verified: true}}); e != "p@x" || !v {
		t.Fatalf("verified primary: got (%q,%v)", e, v)
	}
	if e, v := p.getEmailFromEmailsResult([]GitHubUserEmailInfo{{Email: "s@x", Primary: false, Verified: true}}); e != "s@x" || !v {
		t.Fatalf("verified secondary: got (%q,%v)", e, v)
	}
	if e, v := p.getEmailFromEmailsResult([]GitHubUserEmailInfo{{Email: "u@x", Primary: true, Verified: false}}); e != "" || v {
		t.Fatalf("unverified must be dropped: got (%q,%v)", e, v)
	}
	if e, v := p.getEmailFromEmailsResult([]GitHubUserEmailInfo{{Email: "1+o@users.noreply.github.com", Primary: true, Verified: true}}); e != "" || v {
		t.Fatalf("noreply must be skipped: got (%q,%v)", e, v)
	}
	if e, v := p.getEmailFromEmailsResult(nil); e != "" || v {
		t.Fatalf("empty list: got (%q,%v)", e, v)
	}
}

// --- GitLab -----------------------------------------------------------------

func TestGitLab_EmailVerified(t *testing.T) {
	p := NewGitlabIdProvider("cid", "csec", "https://cb")
	get := func(userJSON string) *UserInfo {
		p.SetHttpClient(cannedClient(map[string]cannedResp{"/api/v4/user": {200, userJSON}}))
		ui, err := p.GetUserInfo(&oauth2.Token{AccessToken: "t"})
		if err != nil {
			t.Fatalf("GetUserInfo: %v", err)
		}
		return ui
	}

	if ui := get(`{"id":7,"username":"gl","name":"GL","state":"active","email":"gl@corp.example","confirmed_at":"2020-01-01T00:00:00Z"}`); !ui.EmailVerified {
		t.Fatal("confirmed_at set + active must be verified")
	}
	if ui := get(`{"id":7,"username":"gl","name":"GL","state":"active","email":"gl@corp.example"}`); ui.EmailVerified {
		t.Fatal("missing confirmed_at must be unverified")
	}
	if ui := get(`{"id":7,"username":"gl","name":"GL","state":"blocked","email":"gl@corp.example","confirmed_at":"2020-01-01T00:00:00Z"}`); ui.EmailVerified {
		t.Fatal("non-active account must be unverified even if confirmed")
	}
}

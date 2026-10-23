// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package otp

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// update rewrites testdata/signin.html from the template: go test ./internal/otp -run Snapshot -update
var update = flag.Bool("update", false, "rewrite the sign-in mail snapshot")

// hanzo is the org as the seed declares it (init_data.json).
var hanzo = &schema.Organization{Name: "hanzo", DisplayName: "Hanzo", WebsiteUrl: "https://hanzo.ai"}

func TestSigninWording(t *testing.T) {
	m, err := signin(hanzo, "ada+x@example.com", "123456", "https://hanzo.ai/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	if m.Org != "hanzo" || m.Channel != Email || m.To != "ada+x@example.com" {
		t.Errorf("addressed %+v", m)
	}
	if m.Subject != "Your Hanzo sign-in link" {
		t.Errorf("subject = %q", m.Subject)
	}
	want := "Sign in to Hanzo\n\n" +
		"Open this link to sign in:\n" +
		"https://hanzo.ai/auth/callback#code=123456&email=ada%2Bx%40example.com\n\n" +
		"Or enter this code: 123456\n\n" +
		"This link and code expire in 10 minutes. Don't share them with anyone.\n" +
		"If you didn't request this, you can ignore this email."
	if m.Body != want {
		t.Errorf("body =\n%q\nwant\n%q", m.Body, want)
	}
	for _, part := range []string{
		`<title>Sign in to Hanzo</title>`,
		`Your sign-in code is 123456.`, // the preheader
		`<img src="https://hanzo.ai/email/mark.png" width="44" height="44" alt="Hanzo"`, // the mark, named
		`href="https://hanzo.ai/auth/callback#code=123456&amp;email=ada%2Bx%40example.com"`,
		`>Sign in</a>`,
		`>123456</div>`,
		`This link and code expire in 10 minutes.`,
		`If you didn't request this, you can ignore this email.`,
		`Hanzo · <a href="https://hanzo.ai"`,
		`<meta name="color-scheme" content="light dark">`,
		`@media (prefers-color-scheme: dark)`,
	} {
		if !strings.Contains(m.HTML, part) {
			t.Errorf("html is missing %q", part)
		}
	}
}

// The name and the site are the org's own: no row names Hanzo for another org, and
// an org with neither is sent a mail that names nobody and loads nothing.
func TestSigninBrandIsTheOrgs(t *testing.T) {
	lux := &schema.Organization{Name: "lux", DisplayName: "Lux Network", WebsiteUrl: "https://lux.network/about"}
	m, err := signin(lux, "ada@example.com", "123456", "https://lux.network/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "Your Lux Network sign-in link" || !strings.HasPrefix(m.Body, "Sign in to Lux Network\n") {
		t.Errorf("subject %q body %q", m.Subject, m.Body)
	}
	if !strings.Contains(m.HTML, `src="https://lux.network/email/mark.png"`) || !strings.Contains(m.HTML, `alt="Lux Network"`) {
		t.Errorf("lux's mark is not lux's own:\n%s", m.HTML)
	}
	if strings.Contains(strings.ToLower(m.HTML+m.Body+m.Subject), "hanzo") {
		t.Errorf("lux's mail names Hanzo")
	}

	for _, website := range []string{"", "http://plain.example", "javascript:alert(1)", "https://user:pw@x.example", "not a url"} {
		bare := &schema.Organization{Name: "bare", WebsiteUrl: website}
		m, err := signin(bare, "ada@example.com", "123456", "https://bare.example/auth/callback")
		if err != nil {
			t.Fatal(err)
		}
		if m.Subject != "Your sign-in link" || !strings.HasPrefix(m.Body, "Sign in\n") {
			t.Errorf("%q: subject %q body %q", website, m.Subject, m.Body)
		}
		if strings.Contains(m.HTML, "<img") || strings.Contains(m.HTML, "javascript") || strings.Contains(m.HTML, "user:pw") {
			t.Errorf("%q: a site that is not an https origin reached the mail:\n%s", website, m.HTML)
		}
		if !strings.Contains(m.HTML, "<title>Sign in</title>") {
			t.Errorf("%q: headline", website)
		}
	}
}

// What a person typed is escaped wherever the mail prints it: an address in the
// link's fragment cannot close the attribute or write a tag.
func TestSigninEscapes(t *testing.T) {
	org := &schema.Organization{Name: "x", DisplayName: `<b>Evil</b> "Co"`, WebsiteUrl: "https://x.example"}
	m, err := signin(org, `a"><script>@example.com`, "123456", "https://x.example/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script>", "<b>Evil</b>"} {
		if strings.Contains(m.HTML, bad) {
			t.Errorf("html carries %q unescaped", bad)
		}
	}
	for _, good := range []string{"email=a%22%3E%3Cscript%3E%40example.com", "&lt;b&gt;Evil&lt;/b&gt;"} {
		if !strings.Contains(m.HTML, good) {
			t.Errorf("html is missing the escaped %q", good)
		}
	}
}

// The mail as it is sent, pinned whole: a change to the design is a change to this
// file, reviewed as one. Open testdata/signin.html in a browser to see it.
func TestSigninSnapshot(t *testing.T) {
	m, err := signin(hanzo, "z@hanzo.ai", "525019", "https://hanzo.ai/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "signin.html")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(m.HTML), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the snapshot (go test ./internal/otp -run Snapshot -update writes it): %v", err)
	}
	if m.HTML != string(want) {
		t.Errorf("the sign-in mail differs from %s; if the change is meant, rerun with -update and review the diff", path)
	}
}

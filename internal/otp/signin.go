// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package otp

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"github.com/hanzoai/iam/pkg/schema"
)

// The sign-in mail: one code and the link that spends it, designed for an email
// client and worded again as plain text beside it.
//
// It is WHITE-LABEL BY THE ORG ROW. The name a reader sees is the org's
// DisplayName and the site is its WebsiteUrl, so hanzo's mail says Hanzo and
// hanzo.ai and a Lux org's says its own; nothing here names a brand. The mark is
// the site's own image at [MarkPath], a raster an email client can show (an SVG
// is not one: Gmail drops it). A site that serves none shows the name as the
// image's alt text.

// MarkPath is where a brand's site serves the square mark its sign-in mail shows:
// a PNG, opaque, at three times its 44px display size.
const MarkPath = "/email/mark.png"

//go:embed signin.html
var signinHTML string

// signinPage is parsed once at init: a template that does not parse is a build
// defect, and html/template's contextual escaping is what keeps an address or a
// link from writing markup into the mail.
var signinPage = template.Must(template.New("signin").Parse(signinHTML))

// mail is what the sign-in page is drawn from.
type mail struct {
	Brand     string // the org's display name, or ""
	Site      string // https://<host> of the org's site, or ""
	Host      string // that host, for the footer
	Mark      string // the site's mark, or "" with no site
	Headline  string
	Preheader string // the line an inbox shows beside the subject
	Link      string // the link with its fragment
	Code      string
	Minutes   int
}

// signin words one sign-in code for one email, from org, with link beside it. The
// link is link plus a fragment carrying the address and the code, which the page it
// opens reads to finish the sign-in; a fragment never reaches a server, so neither
// lands in a request log. The code is printed as well, for a person who reads the
// mail on another device. The expiry is rendered from [TTL].
func signin(org *schema.Organization, to, code, link string) (Message, error) {
	fragment := url.Values{"email": {to}, "code": {code}}.Encode()
	d := mail{
		Brand:     strings.TrimSpace(org.DisplayName),
		Link:      link + "#" + fragment,
		Code:      code,
		Minutes:   int(TTL.Minutes()),
		Preheader: "Your sign-in code is " + code + ".",
	}
	if u := site(org.WebsiteUrl); u != nil {
		d.Site = u.String()
		d.Host = u.Host
		d.Mark = d.Site + MarkPath
	}
	subject := "Your sign-in link"
	d.Headline = "Sign in"
	if d.Brand != "" {
		subject = "Your " + d.Brand + " sign-in link"
		d.Headline = "Sign in to " + d.Brand
	}

	var page strings.Builder
	if err := signinPage.Execute(&page, d); err != nil {
		return Message{}, fmt.Errorf("otp: draw the sign-in mail: %w", err)
	}
	return Message{
		Org:     org.Name,
		Channel: Email,
		To:      to,
		Subject: subject,
		Body: fmt.Sprintf("%s\n\nOpen this link to sign in:\n%s\n\nOr enter this code: %s\n\n"+
			"This link and code expire in %d minutes. Don't share them with anyone.\n"+
			"If you didn't request this, you can ignore this email.",
			d.Headline, d.Link, code, d.Minutes),
		HTML: page.String(),
	}, nil
}

// site is the org's WebsiteUrl as an origin the mail may link to and load its mark
// from: https, a host, no credentials; its path is dropped. Anything else is nil,
// and the mail then carries no mark and no footer link.
func site(raw string) *url.URL {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil
	}
	return &url.URL{Scheme: "https", Host: u.Host}
}

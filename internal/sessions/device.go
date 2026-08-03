// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package sessions

import (
	"strings"

	"github.com/zap-proto/fiber/v3"
)

// deviceOf labels the device a request came from, for the account page's session
// list. It reads the User-Agent and returns something a human recognises among
// their own sessions — "Chrome on macOS", "Safari on iPhone", "hanzo CLI".
func deviceOf(c fiber.Ctx) string { return Device(string(c.Request().Header.UserAgent())) }

// Device derives a coarse label from a User-Agent string. Pure, so the whole
// table below is testable without a request.
//
// COARSE ON PURPOSE. The raw User-Agent is a high-entropy fingerprint that is
// worth nothing to the person reading their own session list and everything to
// anyone who gets a copy of the session table. Storing "Chrome on macOS" answers
// "is that other session mine?" while keeping the row boring if it leaks. Version
// numbers, build ids and the device model are deliberately discarded.
//
// An unrecognised agent is "Unknown device" — never the raw string, which would
// reintroduce exactly the fingerprint this drops, and never empty, which would
// render as a gap in the list.
func Device(ua string) string {
	if ua == "" {
		return "Unknown device"
	}
	if app := nonBrowser(ua); app != "" {
		return app
	}
	browser, os := browserOf(ua), osOf(ua)
	switch {
	case browser != "" && os != "":
		return browser + " on " + os
	case browser != "":
		return browser
	case os != "":
		return os
	}
	return "Unknown device"
}

// nonBrowser names our own clients and the obvious robots before any browser
// sniffing, because every one of them also claims to be Mozilla.
func nonBrowser(ua string) string {
	l := strings.ToLower(ua)
	for _, m := range []struct{ token, label string }{
		{"hanzo-cli", "hanzo CLI"},
		{"hanzo/", "hanzo CLI"},
		{"hanzo-iam", "Hanzo service"},
		{"curl/", "curl"},
		{"wget/", "wget"},
		{"python-requests", "Python client"},
		{"go-http-client", "Go client"},
		{"postman", "Postman"},
		{"insomnia", "Insomnia"},
	} {
		if strings.Contains(l, m.token) {
			return m.label
		}
	}
	return ""
}

// browserOf picks the browser. ORDER IS THE ALGORITHM: every Chromium browser
// also says "Chrome", and Chrome says "Safari", so the most specific claim has
// to be tested first or everything collapses to Chrome/Safari.
func browserOf(ua string) string {
	for _, m := range []struct{ token, label string }{
		{"Edg/", "Edge"},
		{"OPR/", "Opera"},
		{"Brave/", "Brave"},
		{"Arc/", "Arc"},
		{"Vivaldi", "Vivaldi"},
		{"SamsungBrowser", "Samsung Internet"},
		{"CriOS", "Chrome"}, // Chrome on iOS — no "Chrome/" token
		{"FxiOS", "Firefox"},
		{"Firefox", "Firefox"},
		{"Chrome/", "Chrome"},
		{"Chromium", "Chrome"},
		{"Safari", "Safari"},
	} {
		if strings.Contains(ua, m.token) {
			return m.label
		}
	}
	return ""
}

// osOf picks the platform. iPhone/iPad precede "Mac OS X" because iOS Safari
// claims both, and Android precedes Linux for the same reason.
func osOf(ua string) string {
	for _, m := range []struct{ token, label string }{
		{"iPhone", "iPhone"},
		{"iPad", "iPad"},
		{"Android", "Android"},
		{"CrOS", "ChromeOS"},
		{"Mac OS X", "macOS"},
		{"Macintosh", "macOS"},
		{"Windows", "Windows"},
		{"Linux", "Linux"},
	} {
		if strings.Contains(ua, m.token) {
			return m.label
		}
	}
	return ""
}

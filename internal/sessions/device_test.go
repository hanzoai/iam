// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package sessions

import (
	"strings"
	"testing"
)

func TestDevice(t *testing.T) {
	for ua, want := range map[string]string{
		// Chrome says "Safari" and Edge says "Chrome": the most specific claim
		// has to win or every session in the list reads "Chrome on macOS".
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36":                    "Chrome on macOS",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0":            "Edge on Windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15":                    "Safari on macOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1":  "Safari on iPhone",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/140.0.0.0 Mobile/15E148 Safari/604": "Chrome on iPhone",
		"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0":                                                                   "Firefox on Linux",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36":                     "Chrome on Android",
		"hanzo-cli/1.9.35":       "hanzo CLI",
		"curl/8.7.1":             "curl",
		"":                       "Unknown device",
		"something-nobody-knows": "Unknown device",
	} {
		if got := Device(ua); got != want {
			t.Errorf("Device(%.40q) = %q, want %q", ua, got, want)
		}
	}
}

// THE privacy property: the label is coarse. A leaked session table must not
// carry the high-entropy fingerprint the raw header is — no versions, no build
// ids, no device model.
func TestDevice_DropsTheFingerprint(t *testing.T) {
	ua := "Mozilla/5.0 (Linux; Android 14; SM-S928B Build/UP1A.231005.007) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/140.0.7259.51 Mobile Safari/537.36"
	got := Device(ua)
	for _, leak := range []string{"140.0.7259", "SM-S928B", "UP1A", "537.36", "Mozilla"} {
		if strings.Contains(got, leak) {
			t.Errorf("Device leaked %q into %q", leak, got)
		}
	}
	if got != "Chrome on Android" {
		t.Errorf("Device = %q, want %q", got, "Chrome on Android")
	}
}

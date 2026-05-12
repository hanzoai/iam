package util

import "testing"

// TestIsValidOrigin exercises the deployer-pinned allowlist path. The image
// no longer ships hardcoded Hanzo apexes by default — operators set
// IAM_TRUSTED_ORIGIN_SUFFIXES per tenant. The test rebinds the package-
// level slice via a direct assignment to simulate the env-loaded default,
// since `os.Setenv` at test time won't re-run the package init.
func TestIsValidOrigin(t *testing.T) {
	prev := allowedOriginSuffixes
	allowedOriginSuffixes = []string{
		"hanzo.ai",
		"hanzo.app",
		"hanzo.bot",
		"hanzo.chat",
		"hanzo.id",
		"hanzo.agency",
		"hanzo.industries",
		"lux.network",
		"zoo.ngo",
		"zenlm.org",
	}
	defer func() { allowedOriginSuffixes = prev }()

	tests := []struct {
		origin string
		want   bool
	}{
		// Allowed: Hanzo domains
		{"https://app.hanzo.ai", true},
		{"https://hanzo.ai", true},
		{"https://hanzo.id", true},
		{"https://deep.sub.hanzo.ai", true},

		// Allowed: Lux domains
		{"https://lux.network", true},
		{"https://explorer.lux.network", true},

		// Allowed: localhost
		{"http://localhost:3000", true},
		{"http://localhost:5173", true},
		{"http://127.0.0.1:8080", true},

		// Allowed: Zoo
		{"https://zoo.ngo", true},

		// Rejected: arbitrary domains
		{"https://evil.com", false},
		{"https://hanzo.ai.evil.com", false},
		{"https://example.org", false},

		// Rejected: empty
		{"", false},
	}

	for _, tt := range tests {
		got, err := IsValidOrigin(tt.origin)
		if err != nil {
			t.Errorf("IsValidOrigin(%q) unexpected error: %v", tt.origin, err)
			continue
		}
		if got != tt.want {
			t.Errorf("IsValidOrigin(%q) = %v, want %v", tt.origin, got, tt.want)
		}
	}
}

// TestIsValidOrigin_EmptyAllowlist documents the image's shipped-default
// behaviour: with IAM_TRUSTED_ORIGIN_SUFFIXES unset (and therefore
// allowedOriginSuffixes nil), only localhost + 127.0.0.1 + iam-authenticator
// + *.chromiumapp.org are trusted.
func TestIsValidOrigin_EmptyAllowlist(t *testing.T) {
	prev := allowedOriginSuffixes
	allowedOriginSuffixes = nil
	defer func() { allowedOriginSuffixes = prev }()

	cases := []struct {
		origin string
		want   bool
	}{
		{"http://localhost:3000", true},
		{"http://127.0.0.1:8080", true},
		{"https://hanzo.ai", false},
		{"https://evil.com", false},
		{"", false},
	}

	for _, tt := range cases {
		got, err := IsValidOrigin(tt.origin)
		if err != nil {
			t.Errorf("IsValidOrigin(%q) unexpected error: %v", tt.origin, err)
			continue
		}
		if got != tt.want {
			t.Errorf("IsValidOrigin(%q) with empty allowlist = %v, want %v", tt.origin, got, tt.want)
		}
	}
}

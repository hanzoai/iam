package util

import "testing"

func TestIsValidOrigin(t *testing.T) {
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

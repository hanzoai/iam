// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"strings"
	"testing"
)

// A subject has ONE mark. Sending both halves is not a preference order for a
// reader to resolve later — the image wins at the write and the emoji does not
// reach the row, so nothing downstream can rank them differently.
func TestMarkOf_oneAnswerReachesTheRow(t *testing.T) {
	const img = "https://s3.hanzo.ai/avatars/hanzo.png"

	for _, c := range []struct {
		name          string
		avatar, emoji string
		want          Mark
	}{
		{"image alone", img, "", Mark{Avatar: img}},
		{"emoji alone", "", "🦁", Mark{Emoji: "🦁"}},
		{"image beats emoji", img, "🦁", Mark{Avatar: img}},
		{"neither clears the mark", "", "", Mark{}},
		{"blank is not an answer", "   ", "  ", Mark{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := MarkOf(c.avatar, c.emoji)
			if err != nil {
				t.Fatalf("MarkOf(%q, %q): %v", c.avatar, c.emoji, err)
			}
			if got != c.want {
				t.Fatalf("MarkOf(%q, %q) = %+v, want %+v", c.avatar, c.emoji, got, c.want)
			}
		})
	}
}

// A refused half refuses the whole write. Storing the good half of a bad request
// leaves a mark nobody asked for.
func TestMarkOf_refusesRatherThanStoringHalf(t *testing.T) {
	if _, err := MarkOf("javascript:alert(1)", "🦁"); err == nil {
		t.Fatal("a bad image must refuse the write, not fall through to the emoji")
	}
	if _, err := MarkOf("", "not an emoji"); err == nil {
		t.Fatal("a bad emoji must refuse the write")
	}
}

// An image is a reference this service hands to an `<img src>`: an https link, or
// the bytes inline. Anything else is refused at the write, where there is still
// somebody to tell.
func TestAvatarRef(t *testing.T) {
	inline := "data:image/webp;base64,UklGRh4AAABXRUJQ"

	for _, c := range []struct {
		name, raw string
		ok        bool
	}{
		{"https link", "https://s3.hanzo.ai/avatars/hanzo.png", true},
		{"inline webp", inline, true},
		{"inline png", "data:image/png;base64,iVBORw0KGgo=", true},
		{"inline jpeg", "data:image/jpeg;base64,/9j/4AAQSkZJRg==", true},
		{"inline gif", "data:image/gif;base64,R0lGODlhAQAB", true},
		{"empty clears it", "", true},
		{"padded", "  " + inline + "  ", true},

		{"http downgrades a page served over TLS", "http://example.com/a.png", false},
		{"script", "javascript:alert(1)", false},
		{"a document, not an image", "data:text/html;base64,PHNjcmlwdD4=", false},
		{"svg executes", "data:image/svg+xml;base64,PHN2Zz4=", false},
		{"scheme with no image behind it", "https://", false},
		{"an empty inline image", "data:image/png;base64,", false},
		{"a bare path", "/avatars/hanzo.png", false},
		{"a protocol-relative link", "//example.com/a.png", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := AvatarRef(c.raw)
			if c.ok != (err == nil) {
				t.Fatalf("AvatarRef(%q) err = %v, want ok=%v", c.raw, err, c.ok)
			}
			if c.ok && got != strings.TrimSpace(c.raw) {
				t.Fatalf("AvatarRef(%q) = %q, want the value verbatim", c.raw, got)
			}
		})
	}
}

// The bound is on the row, not on whichever client happens to write it. A client
// that enforces its own limit is enforcing a limit for itself only.
func TestAvatarRef_bound(t *testing.T) {
	fits := "data:image/png;base64," + strings.Repeat("A", AvatarLimit-len("data:image/png;base64,"))
	if _, err := AvatarRef(fits); err != nil {
		t.Fatalf("a reference exactly at the limit must be stored: %v", err)
	}
	if _, err := AvatarRef(fits + "A"); err == nil {
		t.Fatal("a reference over the limit must be refused")
	}
}

// One emoji is one sequence, however many runes spell it.
func TestEmoji(t *testing.T) {
	for _, c := range []struct {
		name, raw string
		ok        bool
	}{
		{"a pictograph", "🦁", true},
		{"an older symbol", "⭐", true},
		{"one needing a variation selector", "❤️", true},
		{"a skin tone", "👋🏽", true},
		{"a joined family", "👨‍👩‍👧‍👦", true},
		{"a joined pair with tones", "👨🏻‍❤️‍💋‍👨🏻", true},
		{"a flag", "🇺🇸", true},
		{"a subdivision flag", "🏴󠁧󠁢󠁳󠁣󠁴󠁿", true},
		{"a keycap", "1️⃣", true},
		{"empty means none", "", true},
		{"padded", "  🦁  ", true},

		{"two emoji", "🦁🐯", false},
		{"an emoji and a letter", "🦁a", false},
		{"a letter", "H", false},
		{"a word", "hanzo", false},
		{"prose", "not an emoji", false},
		{"two flags", "🇺🇸🇬🇧", false},
		{"a lone regional indicator", "🇺", false},
		{"a digit without its keycap", "1", false},
		{"a run of pictographs", strings.Repeat("🦁", 12), false},
		{"punctuation", "!", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := Emoji(c.raw)
			if c.ok != (err == nil) {
				t.Fatalf("Emoji(%q) err = %v, want ok=%v", c.raw, err, c.ok)
			}
			if c.ok && got != strings.TrimSpace(c.raw) {
				t.Fatalf("Emoji(%q) = %q, want the value verbatim", c.raw, got)
			}
		})
	}
}

// Normalization settles padding and nothing else. A glyph is not rewritten into
// some other glyph on its way to the row.
func TestEmoji_isNotRewritten(t *testing.T) {
	const withSelector = "❤️" // heart + U+FE0F
	got, err := Emoji(withSelector)
	if err != nil {
		t.Fatalf("Emoji: %v", err)
	}
	if got != withSelector || len([]rune(got)) != 2 {
		t.Fatalf("Emoji(%q) = %q (%d runes), want the sequence verbatim", withSelector, got, len([]rune(got)))
	}
}

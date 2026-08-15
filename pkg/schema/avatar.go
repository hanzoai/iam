// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"fmt"
	"strings"
)

// A mark is how a subject appears across Hanzo, and a subject is a person or an
// organization. Both carry the same pair — `avatar`, an image, and `emoji`, one
// glyph — so what may be in either, and which of the two a screen draws, are
// decided here and read from here rather than restated per entity.
//
// The pair is two fields because it is two types, not because it is two
// questions. `avatar` is published as the OIDC `picture` claim and as a SCIM
// `photos` value, and both are URL-typed by their specs; an emoji put there is
// not a smaller answer, it is an invalid one. At most one half is ever stored,
// so a reader never picks between two answers and no screen has to know a
// precedence rule.
//
// An image is a REFERENCE — a link to one, or the bytes inline as a data URL.
// IAM keeps no blobs of its own: an avatar names an image the same way a person's
// profile photo does.

// AvatarLimit is the longest image reference a mark may hold — 96 KiB, which a
// 256px square crop encodes well inside and a full-size photograph does not. The
// value sits on the subject's row, and that row is read on every sign-in, so the
// bound belongs here where the row is rather than in each client that writes one.
const AvatarLimit = 96 << 10

// Mark is a validated appearance: at most one half non-empty. The field names are
// the row's, so applying one is an assignment and never a translation.
type Mark struct {
	Avatar string
	Emoji  string
}

// MarkOf validates an image reference and an emoji and returns the pair to STORE.
// Both empty clears the mark, which is how a subject goes back to being drawn as
// its initial.
//
// An image wins. It is the thing somebody made, an emoji is what they picked when
// they had not made one yet, and keeping both would leave two answers on the row
// for every future reader to rank.
func MarkOf(avatar, emoji string) (Mark, error) {
	image, err := AvatarRef(avatar)
	if err != nil {
		return Mark{}, err
	}
	if image != "" {
		return Mark{Avatar: image}, nil
	}
	glyph, err := Emoji(emoji)
	if err != nil {
		return Mark{}, err
	}
	return Mark{Emoji: glyph}, nil
}

// AvatarRef validates an image reference. Two forms are usable: an `https` link,
// and a `data:` URL carrying the image inline, which is what a crop performed in
// a browser produces. Empty is legal and means no image.
//
// Everything else is refused rather than stored. A reference is read back into an
// `<img src>`, so a scheme nobody serves images over has no reading there that is
// merely useless — `http` is a downgrade on a page served over TLS, and the rest
// are attempts.
func AvatarRef(raw string) (string, error) {
	ref := strings.TrimSpace(raw)
	switch {
	case ref == "":
		return "", nil
	case len(ref) > AvatarLimit:
		return "", fmt.Errorf("image is %d bytes, over the %d-byte limit: crop or re-encode it smaller", len(ref), AvatarLimit)
	case strings.HasPrefix(ref, "https://") && len(ref) > len("https://"):
		return ref, nil
	case inlineImage(ref):
		return ref, nil
	}
	return "", fmt.Errorf("an avatar must be an https link or an inline image (data:image/png|jpeg|gif|webp;base64,...)")
}

// inlineImage reports whether ref is a base64 data URL of a raster format every
// browser decodes. SVG is not one of them: it is a document, it executes script,
// and it renders in an `<img>` all the same.
func inlineImage(ref string) bool {
	for _, kind := range []string{"png", "jpeg", "gif", "webp"} {
		prefix := "data:image/" + kind + ";base64,"
		if strings.HasPrefix(ref, prefix) && len(ref) > len(prefix) {
			return true
		}
	}
	return false
}

// Emoji validates a single emoji. Empty is legal and means none.
//
// One emoji is one sequence. A pictograph may be tinted by a skin tone, marked as
// emoji rather than text by a variation selector, extended by tag characters into
// a subdivision flag, or joined to further pictographs by a zero-width joiner — a
// family is one mark, not four. Two shapes do not open on a pictograph at all: a
// flag is a pair of regional indicators, and a keycap is an ASCII rune under an
// enclosing keycap.
//
// A field named emoji holds an emoji. Prose in it renders as prose wherever a
// glyph was meant to go, so it is refused at the write instead.
func Emoji(raw string) (string, error) {
	glyph := strings.TrimSpace(raw)
	if glyph == "" {
		return "", nil
	}
	runes := []rune(glyph)
	// The longest standard sequences — a four-person family with skin tones, a
	// subdivision flag — run to about a dozen runes. Past that it is not one mark.
	if len(runes) > 16 {
		return "", notEmoji(raw)
	}
	switch {
	case regional(runes[0]):
		if len(runes) == 2 && regional(runes[1]) {
			return glyph, nil
		}
		return "", notEmoji(raw)
	case keycapBase(runes[0]):
		if !strings.ContainsRune(glyph, keycap) {
			return "", notEmoji(raw)
		}
	case !pictograph(runes[0]):
		return "", notEmoji(raw)
	}
	joined := false // a second pictograph is part of this mark only after a joiner
	for _, r := range runes[1:] {
		switch {
		case r == zwj:
			joined = true
		case sequencing(r):
		case pictograph(r) && joined:
			joined = false
		default:
			return "", notEmoji(raw)
		}
	}
	return glyph, nil
}

func notEmoji(raw string) error {
	return fmt.Errorf("%q is not a single emoji", raw)
}

const (
	zwj    = 0x200D // zero-width joiner
	keycap = 0x20E3 // combining enclosing keycap
)

// sequencing reports whether r extends the pictograph before it rather than
// starting a new one.
func sequencing(r rune) bool {
	switch {
	case r == 0xFE0E || r == 0xFE0F: // text / emoji presentation
		return true
	case r == keycap:
		return true
	case r >= 0x1F3FB && r <= 0x1F3FF: // skin tone
		return true
	case r >= 0xE0020 && r <= 0xE007F: // tags, for subdivision flags
		return true
	}
	return false
}

// keycapBase reports whether r is one of the runes a keycap is built on.
func keycapBase(r rune) bool {
	return (r >= '0' && r <= '9') || r == '#' || r == '*'
}

// regional reports whether r is a regional indicator — the letters a flag is
// spelled with, two to a flag.
func regional(r rune) bool {
	return r >= 0x1F1E6 && r <= 0x1F1FF
}

// pictograph reports whether r is a rune Unicode draws as a picture: the emoji
// planes, plus the older symbol blocks emoji were adopted from. Letters, digits,
// whitespace and punctuation are outside every range, which is the point.
func pictograph(r rune) bool {
	for _, span := range pictographs {
		if r >= span[0] && r <= span[1] {
			return true
		}
	}
	return false
}

var pictographs = [...][2]rune{
	{0x00A9, 0x00A9},   // copyright
	{0x00AE, 0x00AE},   // registered
	{0x203C, 0x203C},   // double exclamation
	{0x2049, 0x2049},   // exclamation question
	{0x2122, 0x2122},   // trade mark
	{0x2139, 0x2139},   // information
	{0x2194, 0x21AA},   // arrows
	{0x231A, 0x23FA},   // watch, hourglass, media controls
	{0x24C2, 0x24C2},   // circled M
	{0x25AA, 0x25FE},   // geometric shapes
	{0x2600, 0x27BF},   // misc symbols and dingbats
	{0x2934, 0x2935},   // curved arrows
	{0x2B00, 0x2BFF},   // misc symbols and arrows
	{0x3030, 0x3030},   // wavy dash
	{0x303D, 0x303D},   // part alternation
	{0x3297, 0x3299},   // circled ideographs
	{0x1F000, 0x1FAFF}, // the emoji planes, flags included
}

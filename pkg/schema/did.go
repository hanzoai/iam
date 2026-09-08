// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "strings"

// The account's DID: one identifier, derived from the OIDC subject, that names
// the same person on chain as in a token.
//
// It is DERIVED, never stored. A stored DID is a second name for a principal
// that can drift from the first — the failure `name` vs `displayName` already
// cost this service once — and it would also make the DID a thing an admin write
// could point at somebody else. The subject IS the identity; this is a rendering
// of it in the syntax a DID resolver reads.

// DIDMethod is the DID method the derivation emits. It names the REGISTRY the
// identifier is anchored in — contracts/identity/DIDRegistry.sol on Lux, whose
// own method string is "lux" — not the brand of the login host. lux.id, hanzo.id,
// zoo.id and pars.id all mint `did:lux:` for the same reason they all mint tokens
// signed by their own key: the brand is who ISSUED the identity, the method is
// where it RESOLVES, and one registry cannot resolve four method names.
const DIDMethod = "lux"

// DID renders an OIDC subject as a decentralized identifier.
//
// The subject has two shapes (subjectOf, internal/oidc/token.go): the stable
// opaque Id — a UUID for every row the v2 path created and for every migrated
// legacy row — or the `<owner>/<name>` natural key for a pre-cutover row that
// carries no Id. Both must render, because both are live `sub` values on tokens
// in the field.
//
// The rendering is `/` → `:`. W3C DID syntax admits `:` inside the
// method-specific-id (it is the segment separator) and admits none of `/`, which
// begins a DID URL path — so `did:lux:hanzo/z` would be a DID URL naming a
// resource under a DID rather than the DID itself, and every resolver would read
// it as such. `did:lux:hanzo:z` is one identifier.
//
// The map is injective over the subjects that exist, so two people can never
// derive one DID: a UUID contains no `:` and no `/`, and the natural key's two
// halves are each drawn from the username alphabet (Username, [a-z0-9._-]), which
// contains neither. A UUID therefore cannot collide with a rendered natural key,
// and two distinct natural keys cannot render alike.
//
// A subject carrying anything outside that alphabet yields "" — no DID, rather
// than a malformed one. A claim that omits itself is read as "this deployment has
// no DID for me"; a syntactically invalid DID is read as an identifier and
// resolved, and what it resolves to is not this person.
func DID(subject string) string {
	if subject == "" || !didSafe(subject) {
		return ""
	}
	return "did:" + DIDMethod + ":" + strings.ReplaceAll(subject, "/", ":")
}

// didSafe reports whether a subject is drawn from the alphabet the rendering is
// injective over: the username characters plus the one separator it rewrites.
func didSafe(subject string) bool {
	for _, r := range subject {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_', r == '/':
		default:
			return false
		}
	}
	return true
}

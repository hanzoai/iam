// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "testing"

// The derivation is pinned rather than described, because both live subject
// shapes reach it — the opaque UUID every v2 row carries, and the
// <owner>/<name> natural key a pre-cutover row still has — and the second one
// is the whole reason the rendering exists.
func TestDID(t *testing.T) {
	for _, tc := range []struct{ name, subject, want string }{
		{"uuid subject passes through", "6f1a3e2c-1f4a-4c0e-9a1b-2f9d4c7b8e01", "did:lux:6f1a3e2c-1f4a-4c0e-9a1b-2f9d4c7b8e01"},
		{"natural key renders the separator", "hanzo/z", "did:lux:hanzo:z"},
		{"username punctuation survives", "lux/zach.kelling-1_x", "did:lux:lux:zach.kelling-1_x"},
		{"empty subject has no identifier", "", ""},
		// A query and a fragment mean something to a resolver, so a subject
		// carrying one must not become an identifier naming something other than
		// the person. A second `/` is not a subject shape IAM produces — there
		// are exactly two — but it renders rather than escapes, which is the
		// point: no input reaches a resolver as a DID URL path.
		{"a second separator renders, it does not escape", "hanzo/z/keys", "did:lux:hanzo:z:keys"},
		{"query is refused", "hanzo/z?x=1", ""},
		{"fragment is refused", "hanzo/z#k", ""},
		{"a colon in the subject is refused", "hanzo:z", ""},
		{"whitespace is refused", "hanzo/ z", ""},
		{"percent-encoding is refused", "hanzo%2Fz", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DID(tc.subject); got != tc.want {
				t.Fatalf("DID(%q) = %q, want %q", tc.subject, got, tc.want)
			}
		})
	}
}

// Two people must never derive one identifier. The claim rests on the subject
// alphabets not overlapping: a UUID carries no ":", and neither half of a
// natural key does either, so the rendered forms cannot collide.
func TestDIDIsInjective(t *testing.T) {
	subjects := []string{
		"hanzo/z", "hanzo/z2", "hanzoz", "hanzo/za", "hanzoz/a", "lux/z",
		"6f1a3e2c-1f4a-4c0e-9a1b-2f9d4c7b8e01", "6f1a3e2c-1f4a-4c0e-9a1b-2f9d4c7b8e02",
	}
	seen := map[string]string{}
	for _, s := range subjects {
		id := DID(s)
		if id == "" {
			t.Fatalf("DID(%q) refused a legitimate subject", s)
		}
		if other, clash := seen[id]; clash {
			t.Fatalf("subjects %q and %q both derive %q", other, s, id)
		}
		seen[id] = s
	}
}

// The method names the REGISTRY, not the brand. Every brand IAM serves mints
// did:lux: because one registry cannot resolve four method names, and the
// on-chain binder refuses to write when a registry reports a different one — so
// this constant and that check have to agree.
func TestDIDMethodIsTheRegistrys(t *testing.T) {
	if DIDMethod != "lux" {
		t.Fatalf("DIDMethod = %q; the DIDRegistry deployment this anchors into serves %q", DIDMethod, "lux")
	}
}

// A wallet becomes a claim value and nothing more: the pair a relying party
// authorizes on, never the key material IAM verified it with.
func TestWalletAsRef(t *testing.T) {
	w := &Wallet{
		Owner: "hanzo", User: "z", Chain: "evm", Address: "0xabc",
		Scheme: "secp256k1-eip191", PublicKey: "04deadbeef", CreatedTime: "2026-09-04T00:00:00Z",
	}
	got := w.AsRef()
	if got != (WalletRef{Chain: "evm", Address: "0xabc"}) {
		t.Fatalf("AsRef() = %+v, want the chain-qualified address alone", got)
	}
}

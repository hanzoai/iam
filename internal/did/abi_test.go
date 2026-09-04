// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package did

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luxfi/crypto/common"
)

// A wrong encoding does not fail here — it fails on chain, as a revert with no
// reason, which is indistinguishable from a signer that was never granted the
// registrar role. So the call data is pinned byte for byte.

// controller is the address in every golden below.
const controller = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"

// The four selectors, cross-checked against an independent keccak
// implementation (viem) over the same canonical signatures. Pinning them here
// is what makes a change to a signature string — a renamed argument, a struct
// field added in the .sol — a red test rather than a silent revert.
func TestSelectors(t *testing.T) {
	for _, tc := range []struct{ sig, want string }{
		{sigCreateDIDFor, "b04a216f"},
		{sigAddVerification, "258cfa7a"},
		{sigAddService, "6a5b36c7"},
		{sigDIDExists, "20dd57a9"},
		{sigMethod, "2c383a9f"},
	} {
		t.Run(tc.sig, func(t *testing.T) {
			if got := hex.EncodeToString(selector(tc.sig)); got != tc.want {
				t.Fatalf("selector(%q) = %s, want %s", tc.sig, got, tc.want)
			}
		})
	}
}

// createDIDFor takes the method-specific-id, NOT the full DID: the registry
// concatenates "did:<method>:" itself, so passing the whole string would
// register did:lux:did:lux:hanzo:z.
func TestEncodeCreateDIDFor(t *testing.T) {
	got := hex.EncodeToString(createDIDFor("hanzo:z", common.HexToAddress(controller)))
	want := join(
		"b04a216f",
		"0000000000000000000000000000000000000000000000000000000000000040", // offset to the identifier
		"0000000000000000000000002c7536e3605d9c16a7a3d7b1898e529396a65c23", // controller
		"0000000000000000000000000000000000000000000000000000000000000007", // len("hanzo:z")
		"68616e7a6f3a7a00000000000000000000000000000000000000000000000000", // "hanzo:z"
	)
	if got != want {
		t.Fatalf("createDIDFor\n got %s\nwant %s", got, want)
	}
}

// didExists takes the FULL DID, because the registry keys every document by
// keccak256 of that whole string.
func TestEncodeDIDExists(t *testing.T) {
	got := hex.EncodeToString(didExists("did:lux:hanzo:z"))
	want := join(
		"20dd57a9",
		"0000000000000000000000000000000000000000000000000000000000000020",
		"000000000000000000000000000000000000000000000000000000000000000f", // len("did:lux:hanzo:z")
		"6469643a6c75783a68616e7a6f3a7a0000000000000000000000000000000000",
	)
	if got != want {
		t.Fatalf("didExists\n got %s\nwant %s", got, want)
	}
}

// The second argument is a DYNAMIC tuple — it holds a `bytes` — so the head
// carries two offsets and the tuple's own `bytes` offset is relative to the
// TUPLE's start, not the call data's. Getting that wrong is the encoding
// mistake that still produces well-formed call data.
func TestEncodeAddVerificationMethod(t *testing.T) {
	addr := common.HexToAddress(controller)
	var account [32]byte
	copy(account[12:], addr[:])
	got := hex.EncodeToString(addVerificationMethod("did:lux:hanzo:z", verification{
		id:          hash32("did:lux:hanzo:z#evm:" + controller),
		methodType:  methodEcdsaRecovery,
		controller:  addr,
		accountHash: account,
	}))
	want := join(
		"258cfa7a",
		"0000000000000000000000000000000000000000000000000000000000000040", // offset to the did
		"0000000000000000000000000000000000000000000000000000000000000080", // offset to the tuple: 64 head + 64 did tail
		"000000000000000000000000000000000000000000000000000000000000000f",
		"6469643a6c75783a68616e7a6f3a7a0000000000000000000000000000000000",
		hex.EncodeToString(idOf("did:lux:hanzo:z#evm:"+controller)),        // id
		"0000000000000000000000000000000000000000000000000000000000000005", // EcdsaSecp256k1RecoveryMethod2020
		"0000000000000000000000002c7536e3605d9c16a7a3d7b1898e529396a65c23", // controller: the wallet itself
		"00000000000000000000000000000000000000000000000000000000000000a0", // offset to publicKeyMultibase, 5 words in
		"0000000000000000000000002c7536e3605d9c16a7a3d7b1898e529396a65c23", // blockchainAccountId
		"0000000000000000000000000000000000000000000000000000000000000000", // no public key: a recovered address is all IAM held
	)
	if got != want {
		t.Fatalf("addVerificationMethod\n got %s\nwant %s", got, want)
	}
}

// Two dynamic fields in one tuple, so the second offset depends on the first
// field's encoded length.
func TestEncodeAddService(t *testing.T) {
	got := hex.EncodeToString(addService("did:lux:hanzo:z", service{
		id:          hash32("did:lux:hanzo:z#iam"),
		serviceType: serviceIssuer,
		endpoint:    "https://hanzo.id",
		data:        []byte("hanzo/z"),
	}))
	want := join(
		"6a5b36c7",
		"0000000000000000000000000000000000000000000000000000000000000040",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"000000000000000000000000000000000000000000000000000000000000000f",
		"6469643a6c75783a68616e7a6f3a7a0000000000000000000000000000000000",
		hex.EncodeToString(idOf("did:lux:hanzo:z#iam")),
		"0000000000000000000000000000000000000000000000000000000000000009", // CredentialIssuer
		"0000000000000000000000000000000000000000000000000000000000000080", // offset to endpoint, 4 words in
		"00000000000000000000000000000000000000000000000000000000000000c0", // offset to data, past the endpoint
		"0000000000000000000000000000000000000000000000000000000000000010", // len("https://hanzo.id")
		"68747470733a2f2f68616e7a6f2e696400000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000007", // len("hanzo/z") — the subject at the issuer
		"68616e7a6f2f7a00000000000000000000000000000000000000000000000000",
	)
	if got != want {
		t.Fatalf("addService\n got %s\nwant %s", got, want)
	}
}

// A value shorter than a word is right-padded; a value that lands exactly on a
// word boundary gets NO padding word, and one byte past it gets a whole extra
// word. Both edges, because an off-by-one here shifts every field after it.
func TestBytesTailPadding(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantLen int
	}{
		{"", 32},
		{"a", 64},
		{strings.Repeat("a", 31), 64},
		{strings.Repeat("a", 32), 64},
		{strings.Repeat("a", 33), 96},
	} {
		if got := len(bytesTail([]byte(tc.in))); got != tc.wantLen {
			t.Fatalf("bytesTail(%d bytes) = %d bytes, want %d", len(tc.in), got, tc.wantLen)
		}
	}
}

// idOf renders the bytes32 id of a DID URL fragment, for the goldens above.
func idOf(fragment string) []byte {
	h := hash32(fragment)
	return h[:]
}

func join(parts ...string) string { return strings.Join(parts, "") }

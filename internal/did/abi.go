// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package did

import (
	"math/big"

	luxcrypto "github.com/luxfi/crypto"
	"github.com/luxfi/crypto/common"
)

// Solidity call encoding for the four DIDRegistry methods this package uses.
//
// Hand-written, and small enough to read in one sitting, because the alternative
// is a generated binding — which would pull an EVM client library into a service
// whose job is issuing tokens. Four calls, three of which take one string and one
// struct, do not pay for that.
//
// SELECTORS ARE DERIVED, NEVER PASTED. Each is keccak256 of the canonical
// signature string below, computed at init. A pasted four-byte constant is a
// value nobody can check by reading it: transpose two hex digits and the call
// still encodes, still sends, and reverts on chain as an unknown method — which
// looks exactly like a permissions failure. The signature string is the thing a
// reader can compare against the .sol file.

// The canonical signatures, verbatim from contracts/identity/DIDRegistry.sol.
// A tuple argument is spelled by its component types in declaration order, which
// is what Solidity hashes: VerificationMethod is
// (bytes32 id, uint8 methodType, address controller, bytes publicKeyMultibase,
// bytes32 blockchainAccountId) and Service is
// (bytes32 id, uint8 serviceType, string endpoint, bytes data).
const (
	sigCreateDIDFor        = "createDIDFor(string,address)"
	sigAddVerification     = "addVerificationMethod(string,(bytes32,uint8,address,bytes,bytes32))"
	sigAddService          = "addService(string,(bytes32,uint8,string,bytes))"
	sigDIDExists           = "didExists(string)"
	sigMethod              = "method()"
	wordLen                = 32
	verificationFieldCount = 5
	serviceFieldCount      = 4
)

// selector is the four-byte function selector of a canonical signature.
func selector(sig string) []byte { return luxcrypto.Keccak256([]byte(sig))[:4] }

// createDIDFor encodes createDIDFor(identifier, controller). The identifier is
// the method-specific-id — the registry concatenates "did:<method>:" onto it
// itself, so the FULL DID must not be passed here.
func createDIDFor(identifier string, controller common.Address) []byte {
	out := selector(sigCreateDIDFor)
	// Head: two words — the offset to the string tail, then the address.
	out = append(out, word(big.NewInt(2*wordLen))...)
	out = append(out, addressWord(controller)...)
	return append(out, bytesTail([]byte(identifier))...)
}

// addVerificationMethod encodes addVerificationMethod(did, method). did is the
// FULL "did:lux:…" string, because the registry keys every document by
// keccak256 of it.
func addVerificationMethod(did string, m verification) []byte {
	tuple := m.encode()
	out := selector(sigAddVerification)
	// Head: offset to the did string, then offset to the tuple. Both arguments
	// are dynamic (the tuple contains `bytes`), so both are references.
	out = append(out, word(big.NewInt(2*wordLen))...)
	didTail := bytesTail([]byte(did))
	out = append(out, word(big.NewInt(int64(2*wordLen+len(didTail))))...)
	out = append(out, didTail...)
	return append(out, tuple...)
}

// addService encodes addService(did, service).
func addService(did string, s service) []byte {
	tuple := s.encode()
	out := selector(sigAddService)
	out = append(out, word(big.NewInt(2*wordLen))...)
	didTail := bytesTail([]byte(did))
	out = append(out, word(big.NewInt(int64(2*wordLen+len(didTail))))...)
	out = append(out, didTail...)
	return append(out, tuple...)
}

// didExists encodes the view call that reports whether a document is already
// registered. It is what keeps a re-link from re-creating a DID the registry
// would revert on.
func didExists(did string) []byte {
	out := selector(sigDIDExists)
	out = append(out, word(big.NewInt(wordLen))...)
	return append(out, bytesTail([]byte(did))...)
}

// registryMethod encodes the view call returning the registry's OWN method
// string. See Registry.check for why it is asked.
func registryMethod() []byte { return selector(sigMethod) }

// verification is the VerificationMethod struct the registry stores.
type verification struct {
	id          [32]byte
	methodType  uint8
	controller  common.Address
	publicKey   []byte
	accountHash [32]byte
}

// encode lays the struct out as a dynamic ABI tuple: four head words (the
// `bytes` field carries an offset instead of a value) followed by the bytes
// tail. Offsets inside a tuple are relative to the TUPLE's own start, not to
// the call data's.
func (v verification) encode() []byte {
	out := make([]byte, 0, verificationFieldCount*wordLen+wordLen+len(v.publicKey))
	out = append(out, v.id[:]...)
	out = append(out, word(big.NewInt(int64(v.methodType)))...)
	out = append(out, addressWord(v.controller)...)
	out = append(out, word(big.NewInt(verificationFieldCount*wordLen))...)
	out = append(out, v.accountHash[:]...)
	return append(out, bytesTail(v.publicKey)...)
}

// service is the Service struct the registry stores.
type service struct {
	id          [32]byte
	serviceType uint8
	endpoint    string
	data        []byte
}

// encode lays the struct out as a dynamic ABI tuple. Two of its four fields are
// dynamic, so the second offset depends on the first field's encoded length.
func (s service) encode() []byte {
	endpoint := bytesTail([]byte(s.endpoint))
	out := make([]byte, 0, serviceFieldCount*wordLen+len(endpoint)+wordLen+len(s.data))
	out = append(out, s.id[:]...)
	out = append(out, word(big.NewInt(int64(s.serviceType)))...)
	out = append(out, word(big.NewInt(serviceFieldCount*wordLen))...)
	out = append(out, word(big.NewInt(int64(serviceFieldCount*wordLen+len(endpoint))))...)
	out = append(out, endpoint...)
	return append(out, bytesTail(s.data)...)
}

// bytesTail encodes a dynamic `bytes`/`string` value: its length, then its
// content right-padded to a whole number of words.
func bytesTail(b []byte) []byte {
	out := word(big.NewInt(int64(len(b))))
	out = append(out, b...)
	if pad := (wordLen - len(b)%wordLen) % wordLen; pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

// word left-pads an unsigned integer into one 32-byte ABI word.
func word(i *big.Int) []byte {
	out := make([]byte, wordLen)
	i.FillBytes(out)
	return out
}

// addressWord left-pads a 20-byte address into one 32-byte ABI word.
func addressWord(a common.Address) []byte {
	out := make([]byte, wordLen)
	copy(out[wordLen-common.AddressLength:], a[:])
	return out
}

// hash32 is keccak256 as a fixed array, the shape the registry's bytes32 ids
// take.
func hash32(s string) [32]byte {
	var out [32]byte
	copy(out[:], luxcrypto.Keccak256([]byte(s)))
	return out
}

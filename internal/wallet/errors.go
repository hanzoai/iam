// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"errors"
	"fmt"
	"strings"

	luxcrypto "github.com/luxfi/crypto"
	wc "github.com/luxwallet/connect/go/walletconnect"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/oidc"
)

// Stable machine-readable error codes returned on wallet sign-in refusals
// alongside the human-facing msg. Callers (Pay, hanzo.id, @hanzo/iam) branch
// on `code` without coupling to prose.
const (
	CodeInvalidRequest     = "web3_invalid_request"
	CodeUnsupportedChain   = "web3_unsupported_chain"
	CodeChallengeInvalid   = "web3_challenge_invalid"
	CodeDomainMismatch     = "web3_domain_mismatch"
	CodeChainMismatch      = "web3_chain_mismatch"
	CodeMalformedMessage   = "web3_malformed_message"
	CodeAddressMismatch    = "web3_address_mismatch"
	CodeInvalidSignature   = "web3_invalid_signature"
	CodeWalletLinked       = "web3_wallet_already_linked"
	CodeNoAccount          = "web3_account_not_found"
	CodeSignupDisabled     = "web3_signup_disabled"
	CodeInvalidRedirectURI = "invalid_redirect_uri"
	CodePKCERequired       = "pkce_required"
)

// verifyError wraps a cryptographic / message reason from VerifyProof so the
// HTTP boundary emits a structured error code while keeping the exact message.
type verifyError struct {
	reason wc.Reason
}

func (e *verifyError) Error() string {
	return fmt.Sprintf("web3: verification failed: %s", e.reason)
}

// errorCode maps a verify / mint failure to its structured error code.
func errorCode(err error) string {
	var ve *verifyError
	if errors.As(err, &ve) {
		switch ve.reason {
		case wc.ReasonAddressMismatch:
			return CodeAddressMismatch
		case wc.ReasonDomainMismatch:
			return CodeDomainMismatch
		case wc.ReasonNonceMismatch, wc.ReasonExpired, wc.ReasonNotYetValid:
			return CodeChallengeInvalid
		case wc.ReasonMalformedMessage:
			return CodeMalformedMessage
		default:
			return CodeInvalidSignature
		}
	}
	switch {
	case errors.Is(err, errChallenge):
		return CodeChallengeInvalid
	case errors.Is(err, errDomain):
		return CodeDomainMismatch
	case errors.Is(err, errChain):
		return CodeChainMismatch
	case errors.Is(err, errMessage):
		return CodeMalformedMessage
	case errors.Is(err, errLinked):
		return CodeWalletLinked
	case errors.Is(err, errNoAccount):
		return CodeNoAccount
	case errors.Is(err, errNoSignup):
		return CodeSignupDisabled
	case errors.Is(err, errForbidden), errors.Is(err, errDeleted):
		return oidc.CodeAccountNotPermitted
	case errors.Is(err, errRouting):
		return CodeInvalidRequest
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "invalid redirect_uri"):
		return CodeInvalidRedirectURI
	case strings.Contains(msg, "PKCE"):
		return CodePKCERequired
	case strings.Contains(msg, "not permitted to sign in") || strings.Contains(msg, "beta"):
		return oidc.CodeAccessDenied
	case strings.Contains(msg, "unsupported chain"):
		return CodeUnsupportedChain
	default:
		return CodeInvalidRequest
	}
}

// verifyFail writes a 400 refusal carrying both the exact human message and its
// stable machine-readable code.
func verifyFail(c *zip.Ctx, err error) error {
	return httpx.ErrCode(c, err.Error(), errorCode(err))
}

// EIP55 formats a 20-byte hex EVM address according to ERC-55 mixed-case
// checksum encoding. Non-EVM or non-20-byte-hex inputs are returned trimmed.
func EIP55(address string) string {
	s := strings.TrimSpace(address)
	if len(s) != 42 || (s[:2] != "0x" && s[:2] != "0X") {
		return s
	}
	lower := strings.ToLower(s[2:])
	for i := 0; i < 40; i++ {
		c := lower[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return s
		}
	}
	hash := luxcrypto.Keccak256([]byte(lower))
	var out [42]byte
	out[0], out[1] = '0', 'x'
	for i := 0; i < 40; i++ {
		c := lower[i]
		nibble := hash[i/2] >> 4
		if i%2 == 1 {
			nibble = hash[i/2] & 0x0f
		}
		if c >= 'a' && c <= 'f' && nibble >= 8 {
			c = c - 'a' + 'A'
		}
		out[2+i] = c
	}
	return string(out[:])
}

// CanonicalAddress normalizes a wallet address into its single storage and
// lookup key: lowercase 0x-hex for EVM, trimmed case-preserving string for
// case-sensitive base58/bech32/SS58 chains (Solana, Bitcoin, TON, XRP, etc.).
func CanonicalAddress(chain wc.Chain, address string) string {
	return canonical(chain, address)
}

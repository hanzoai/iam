// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package capauth

import (
	"errors"
	"time"

	"github.com/zap-proto/go/cap"
)

// LibVerifier is the library-layer verifier. It composes
// cap.Verifier (signature/expiry/revocation/chain-walk) with the
// helper-level invariants the cap runtime does not enforce on its own:
//
//   - Audience caveats must name THIS resource server.
//   - Chain depth must be ≤ ChainDepthMax (and ≤ any CaveatMaxDepth on
//     the chain).
//   - Unknown CaveatKind values fail-closed per SPEC.md §2.3 step 4.
//   - Time source is pluggable via Clock for deterministic tests.
//
// Name disambiguation: the cap runtime exports `cap.Verifier`; this
// package exports `capauth.LibVerifier` to avoid shadowing the upstream
// type. Most callers see only `Verifier` because LibVerifier is the
// exported alias below.
type LibVerifier struct {
	// Store backs the IsRevoked check. Nil means "treat everything as
	// non-revoked" (only sane in tests).
	Store RevocationStore

	// Registry resolves issuer hashes to raw public-key bytes. Nil is a
	// configuration error and Verify returns ErrIssuerUnknown.
	Registry IssuerRegistry

	// Clock supplies the current time for expiry checks. Defaults to
	// SystemClock if nil.
	Clock Clock

	// Identity is the 32-byte hash of THIS resource server's public
	// identity. Compared in constant time against CaveatAudience entries
	// in the cap. Setting Identity to the zero hash disables the
	// audience check — useful for IAM itself (which mints caps for
	// anyone) and for resource servers that haven't onboarded an
	// identity yet, but production resource servers MUST set it.
	Identity [32]byte

	// MLDSA65Ctx is the FIPS 204 §5.2 domain-separation context string
	// that ML-DSA-65 signers used at issue time. The verifier passes it
	// into mldsa65.Verify so a cap minted with ctx="hanzo-iam/cap/v1"
	// only verifies under a verifier configured with the same ctx —
	// preventing cross-protocol signature replay.
	//
	// Leaving this empty is legal (matches an empty signer ctx) but
	// cryptographically discouraged for production deployments.
	MLDSA65Ctx []byte
}

// Verifier is the canonical library-layer verifier name; consumers see
// `capauth.Verifier` rather than `LibVerifier` in their code, with the
// long name kept as a type alias for documentation symmetry.
type Verifier = LibVerifier

// VerifyParams carries the per-call parameters Verify needs alongside
// the static configuration on the Verifier struct.
type VerifyParams struct {
	// Leaf is the cap the wielder is presenting.
	Leaf cap.Cap

	// Chain is the chain of parent caps from Leaf.Parent up to root.
	// chain[0] is Leaf's parent; chain[len-1] is the root (Parent ==
	// zero). An empty Chain means Leaf is itself a root.
	Chain []cap.Cap

	// RequiredOp is the bitmask of operations the caller is about to
	// perform. Verify rejects if Leaf.Permissions does not cover every
	// bit set here.
	RequiredOp uint64

	// Target is the 32-byte hash of the object the caller is acting on.
	// Verify rejects if Leaf.Target does not match.
	Target [32]byte

	// Holder is the 32-byte hash of the holder presenting the cap.
	// Verify rejects if Leaf.Holder does not match. v1 has no
	// proof-of-possession; this is a sanity check that the holder field
	// names the principal the caller's higher-level auth layer believes
	// is acting.
	Holder [32]byte
}

// Verify validates the cap chain against the verifier's static
// configuration and the per-call params. Returns nil on success; on any
// failure, the request must be treated as unauthenticated. The returned
// error is the most specific sentinel describing the failure mode.
func (v *LibVerifier) Verify(p VerifyParams) error {
	if v == nil {
		return errors.New("capauth: Verify on nil Verifier")
	}
	if v.Registry == nil {
		return cap.ErrIssuerUnknown
	}

	// Chain depth: depth is leaf + len(chain). v1.0 cap runtime does
	// not impose a ceiling; we layer one here so unbounded chains are a
	// definite 401 instead of an O(N) crypto stall.
	if 1+len(p.Chain) > ChainDepthMax {
		return ErrChainTooDeep
	}

	// Pluggable clock; default to time.Now.
	now := time.Now().Unix()
	if v.Clock != nil {
		now = v.Clock.Now().Unix()
	}

	// Build the runtime Verifier with our injected hooks. SchemeVerify
	// dispatches on the sig[AlgTagOffset] byte; we handle the ML-DSA-65
	// arm here and let the dispatcher fall back to ed25519 for the
	// bootstrap scheme + the zero-tag legacy case.
	ctxCopy := v.MLDSA65Ctx
	rv := cap.Verifier{
		IsRevoked: func(id [32]byte) bool {
			if v.Store == nil {
				return false
			}
			return v.Store.IsRevoked(id)
		},
		IssuerKey: v.Registry.Lookup,
		SchemeVerify: func(scheme cap.Scheme, pub []byte, payload []byte, sig [cap.SigSize]byte) error {
			switch scheme {
			case cap.SchemeMLDSA65:
				return VerifyMLDSA65(pub, payload, ctxCopy, sig)
			default:
				return cap.ErrUnhandledScheme
			}
		},
	}

	// Delegate the structural / signature / expiry / chain-walk work
	// to the cap runtime; it is the canonical verifier for these
	// concerns and we do not re-implement them.
	if err := rv.VerifyChain(p.Leaf, p.Chain, p.RequiredOp, p.Target, p.Holder, now); err != nil {
		return err
	}

	// --- Helper-level invariants the cap runtime does not check -----------

	// Walk every cap in the chain (leaf first, then parents) to:
	//   1. Reject unknown CaveatKind values.
	//   2. Honour CaveatAudience.
	//   3. Honour CaveatMaxDepth (decrement-walked).
	//   4. Cross-check CaveatExpiresAt against the wall clock (the cap
	//      runtime already checks the cap's ExpiresAt field; a caveat
	//      MAY tighten further).
	chain := append([]cap.Cap{p.Leaf}, p.Chain...)
	for hop, c := range chain {
		caveats := c.Caveats()
		for _, cv := range caveats {
			if !knownCaveatKind(cv.Kind) {
				return ErrCaveatUnknown
			}
		}

		// Audience: if a caveat names a service identity, this verifier
		// must be that identity (or have Identity == zero, which
		// explicitly opts out of audience checks — only IAM does this).
		if aud, ok := audienceFromCaveats(caveats); ok {
			if v.Identity != [32]byte{} && !bytesEqualConstantTime(aud[:], v.Identity[:]) {
				return ErrAudienceMismatch
			}
		}

		// Expiry caveat (in addition to the cap's own ExpiresAt field).
		if exp, ok := expiryFromCaveats(caveats); ok {
			if uint64(now) > exp {
				return cap.ErrExpired
			}
		}

		// MaxDepth caveat: a hop-N cap saying "MaxDepth=k" means "I
		// permit k more attenuations downstream". If hop=0 (the leaf)
		// holds MaxDepth=k, then strictly less-than-k caps may have
		// been attenuated below it — but there is no "below" a leaf, so
		// the leaf's own MaxDepth is a budget for FUTURE attenuations
		// the leaf-holder may do, not a check at this verifier.
		//
		// At hop=h>0, the chain has h hops below this cap. The cap's
		// MaxDepth at the time of issue MUST have been ≥ h for the
		// chain to be valid; verify it now.
		if hop > 0 {
			if d, ok := maxDepthFromCaveats(caveats); ok {
				if int(d) < hop {
					return ErrChainTooDeep
				}
			}
		}
	}

	return nil
}

// knownCaveatKind reports whether k is a CaveatKind defined in
// capabilities_kinds.md v1.0. Used to fail-closed on unknown kinds per
// SPEC.md §2.3 step 4.
func knownCaveatKind(k cap.CaveatKind) bool {
	switch k {
	case cap.CaveatExpiresAt,
		cap.CaveatMaxAmount,
		cap.CaveatDestChain,
		cap.CaveatRateLimit,
		cap.CaveatIPCIDR,
		cap.CaveatAssetID,
		cap.CaveatOpAllow,
		cap.CaveatMaxDepth,
		cap.CaveatAudience,
		cap.CaveatNonceHash:
		return true
	default:
		return false
	}
}

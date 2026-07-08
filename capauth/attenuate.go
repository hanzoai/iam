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
	"encoding/binary"
	"errors"

	"github.com/zap-proto/go/cap"
)

// AttenuateParams describes a child cap to be derived from a parent.
//
// The cap runtime's cap.Attenuate enforces the wire-level invariants:
// child's Issuer = parent's Holder, child's Permissions ⊆ parent's,
// expiry can only tighten. This struct + Attenuate add the helper-level
// invariants:
//
//   - Audience (CaveatAudience) may only narrow from the parent. A
//     child with the same audience or no audience is fine; a child
//     trying to set an audience different from the parent's is
//     rejected with ErrCaveatWidened.
//
//   - MaxDepth (CaveatMaxDepth) is decremented automatically and
//     refuses to go below 1 (which would forbid the child from
//     attenuating further, a legitimate ask). A request to widen
//     MaxDepth above the parent's remaining budget is
//     ErrCaveatWidened.
//
//   - ExpiresAt may only shrink (mirrors cap.Attenuate's own behaviour
//     but enforced here too so the helper-level error is friendly).
type AttenuateParams struct {
	// NewHolder is the 32-byte hash of the wielder's public key the
	// child cap is for.
	NewHolder [32]byte

	// Permissions is the bitmask of operations to grant the child.
	// MUST be a subset of the parent's; cap.Attenuate intersects, so
	// passing 0xFFFF... is equivalent to "inherit all".
	Permissions uint64

	// Audience, if set, narrows the audience to a more specific
	// resource server. MUST equal the parent's audience or be the
	// child's own narrowing under the parent's. A child cap MAY add an
	// audience that the parent didn't carry (that's narrowing the
	// implicit "anyone" to "this one"), but a child MAY NOT change a
	// parent's existing audience to a different one. v1 enforces the
	// strict rule "audience may be added but never changed" — that's
	// the only safe option without a richer audience-hierarchy schema.
	Audience [32]byte

	// ExpiresAt, if non-zero, is the child's expiry. cap.Attenuate
	// floors this to the parent's; we additionally refuse to *raise*
	// it via the helper boundary so the caller's error is friendly.
	ExpiresAt int64

	// MaxDepth is the child's remaining-hops budget. 0 means "inherit
	// (parent's - 1)" if the parent carries a MaxDepth caveat, or
	// "unbounded by caveat" if the parent does not. A positive
	// MaxDepth that exceeds (parent's - 1) is ErrCaveatWidened.
	MaxDepth uint8

	// ExtraCaveats are caveats the caller wants to add beyond the
	// helper-managed kinds. Same duplicate-vs-helper rule as
	// IssueParams.
	ExtraCaveats []cap.Caveat
}

// Attenuate derives a child cap from parent. The Issuer's Signer MUST be
// the parent's Holder's signing key — cap.Attenuate enforces this and
// returns ErrChainBroken if violated, but the more common failure mode
// at this layer is the caller forgetting to swap Signers between the
// "I'm minting" and "I'm delegating" call sites; the helper-level error
// surfaces in cap.Attenuate's return as ErrChainBroken regardless.
func (iss *Issuer) Attenuate(parent cap.Cap, p AttenuateParams) (cap.Cap, error) {
	if iss == nil || iss.Signer == nil {
		return cap.Cap{}, errors.New("capauth: Attenuate called on nil Issuer or nil Signer")
	}
	if iss.Scheme == SchemeMLDSA65 {
		return cap.Cap{}, ErrSchemeWireIncompat
	}

	parentCaveats := parent.Caveats()

	// --- Audience monotonicity --------------------------------------------
	parentAud, parentHasAud := audienceFromCaveats(parentCaveats)
	if parentHasAud {
		switch {
		case p.Audience == [32]byte{}:
			// Inherit parent audience.
			p.Audience = parentAud
		case p.Audience != parentAud:
			// v1: child may NOT change an existing audience. Permitting
			// "narrower-than-parent" would require a richer hierarchy
			// (e.g. service IDs that subset other service IDs); we don't
			// have that, so the safe rule is strict equality.
			return cap.Cap{}, ErrCaveatWidened
		}
	}

	// --- Depth monotonicity -----------------------------------------------
	parentDepth, parentHasDepth := maxDepthFromCaveats(parentCaveats)
	childDepth := p.MaxDepth
	switch {
	case parentHasDepth && parentDepth == 0:
		// Wire-level "0" means "no further attenuations". The parent
		// already forbade us from minting a child — refuse before we
		// produce something that would fail Verify.
		return cap.Cap{}, ErrCaveatWidened
	case parentHasDepth:
		// Parent permits parentDepth-1 more attenuations downstream.
		// If the caller requested a specific MaxDepth, it MUST not
		// exceed parentDepth - 1.
		remaining := parentDepth - 1
		if childDepth == 0 {
			childDepth = remaining
		} else if childDepth > remaining {
			return cap.Cap{}, ErrCaveatWidened
		}
	default:
		// Parent did not carry a MaxDepth caveat. Caller may set one.
	}

	// --- Expiry monotonicity ----------------------------------------------
	// cap.Attenuate already floors the child's expiry to the parent's;
	// we additionally check at the helper boundary so the caller learns
	// at mint-time that they tried to raise it.
	parentExp := parent.ExpiresAt()
	if parentExp != 0 && p.ExpiresAt != 0 && uint64(p.ExpiresAt) > parentExp {
		return cap.Cap{}, ErrCaveatWidened
	}

	// --- Permissions monotonicity at the helper boundary ------------------
	// cap.Attenuate intersects with the parent's permissions; the helper
	// surfaces the misuse upfront so callers can fix calling code rather
	// than discovering the child's perms are smaller than they asked for
	// at verify time.
	if p.Permissions&^parent.Permissions() != 0 {
		return cap.Cap{}, ErrPermsWidened
	}

	// --- Compose caveats --------------------------------------------------
	// Child caveats are stored independently of parent caveats: the
	// chain-walk evaluates the union, so the child SHOULD NOT re-emit a
	// parent's caveat unless tightening it. For v1:
	//
	//   - Audience: omit on the child if the parent already carries one
	//     (parent's caveat is in the chain). Emit only if the child
	//     narrows from "no parent audience" to "this audience".
	//   - MaxDepth: re-emit the decremented value on the child so the
	//     chain-walk's minimum-along-chain is the actual remaining
	//     budget; the parent's value alone would let the child grant
	//     children with the SAME depth, defeating monotonic narrowing.
	//   - ExpiresAt: re-emit only if it tightens the parent's. The
	//     cap.Cap's own ExpiresAt field carries the floored value from
	//     cap.Attenuate's contract.
	_ = parentAud // claim live; logical use is in the audience-monotonicity check above
	emitAud := [32]byte{}
	if !parentHasAud && p.Audience != [32]byte{} {
		emitAud = p.Audience
	}
	emitExp := int64(0)
	if p.ExpiresAt != 0 && (parentExp == 0 || uint64(p.ExpiresAt) < parentExp) {
		emitExp = p.ExpiresAt
	}
	helperParams := IssueParams{
		Audience:     emitAud,
		ExpiresAt:    emitExp,
		MaxDepth:     childDepth,
		ExtraCaveats: p.ExtraCaveats,
	}
	caveats, err := buildHelperCaveats(helperParams, helperContext{forAttenuation: true})
	if err != nil {
		return cap.Cap{}, err
	}

	// cap.Attenuate enforces signer.Public() == parent.Holder(); on
	// success the child's Issuer field becomes signer.Public(), which is
	// the parent's Holder, satisfying the chain-link rule at verify time.
	//
	// Re-grant PermAttenuate on the child so it too may delegate further
	// down the chain (bounded by MaxDepth + ChainDepthMax). cap.Attenuate
	// intersects with the parent's permissions, so this bit only survives
	// when the parent itself carried it — a non-delegable parent still
	// yields a non-delegable child.
	return cap.Attenuate(parent, p.NewHolder, p.Permissions|cap.PermAttenuate, caveats, p.ExpiresAt, iss.Signer)
}

// _ unused-suppression sentinel for the binary import.
var _ = binary.LittleEndian

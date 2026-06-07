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
	"time"

	"github.com/zap-proto/go/cap"
)

// IssueParams describes a single capability the issuer should mint.
//
// The shape is deliberately distinct from cap.Issuance so the library
// layer can introduce policy that the wire layer doesn't carry: e.g. the
// Audience field below becomes a CaveatAudience entry in the underlying
// Issuance, but at this layer it's named for what it is.
type IssueParams struct {
	// Kind is the CapKind from capabilities_kinds.md. Issuers MUST pass a
	// known kind; the cap runtime does not enforce a closed set, but
	// resource servers fail-closed on unknown kinds and so will Verify.
	Kind cap.CapKind

	// Target is the 32-byte BLAKE3 hash of the object this cap grants
	// over. The verifier compares this against the resource server's
	// notion of the target it serves; mismatch is ErrTargetMismatch.
	Target [32]byte

	// Holder is the 32-byte hash of the wielder's public key. The wire
	// format does not bind to the keypair unless the caller layers
	// proof-of-possession on top of this package (see CaveatBearerKey
	// note in capauth.go); v1 trusts possession of the cap bytes.
	Holder [32]byte

	// Permissions is the bitmask of operations this cap allows on
	// Target. See capabilities_kinds.md for per-Kind bit assignments.
	Permissions uint64

	// Audience, if non-zero, is the 32-byte hash of the resource server
	// this cap is intended for. Encoded as a CaveatAudience entry in the
	// minted cap. Verifiers reject when the cap's audience does not name
	// them.
	Audience [32]byte

	// NotBefore, if non-zero, is the Unix-seconds floor before which the
	// cap is not yet valid. Encoded as a CaveatNotBefore-style entry —
	// see the caveat-kind allocation note below.
	NotBefore int64

	// ExpiresAt, if non-zero, is the Unix-seconds expiry. Encoded both
	// in the cap's ExpiresAt field (for the runtime's fast-path check)
	// and as a CaveatExpiresAt entry (which the verifier ANDs over the
	// whole chain).
	ExpiresAt int64

	// MaxDepth, if non-zero, caps how many further attenuations this
	// cap may produce. Encoded as a CaveatMaxDepth entry.
	MaxDepth uint8

	// ExtraCaveats appends caveats the caller already knows about. The
	// helper-side rule is: helper-managed caveats (Audience, NotBefore,
	// ExpiresAt, MaxDepth) are emitted automatically and MUST NOT appear
	// in ExtraCaveats, or Issue returns ErrCaveatDuplicate.
	ExtraCaveats []cap.Caveat
}

// ErrCaveatDuplicate is returned by Issue when the caller supplies an
// ExtraCaveat whose kind is also being emitted by a helper-managed field.
// Avoids the silent ambiguity of two caveats of the same kind in one cap
// (which the wire format allows but the verifier evaluates as AND, which
// is rarely what the issuer meant).
var ErrCaveatDuplicate = errors.New("capauth: extra caveat duplicates helper-managed kind")

// Issue mints a new root cap. The caller MUST hold the signing key; the
// Issuer's Signer is what signs the wire bytes.
//
// Root caps have Parent = zero. For derived caps, use Attenuate.
//
// Scheme dispatch is the Signer's responsibility: the Signer writes the
// algorithm tag at cap.AlgTagOffset of the SigSize footer so verifiers
// can pick the matching primitive. Issue itself is scheme-agnostic.
func (iss *Issuer) Issue(p IssueParams) (cap.Cap, error) {
	if iss == nil || iss.Signer == nil {
		return cap.Cap{}, errors.New("capauth: Issue called on nil Issuer or nil Signer")
	}
	caveats, err := buildHelperCaveats(p, helperContext{forAttenuation: false})
	if err != nil {
		return cap.Cap{}, err
	}
	now := iss.clockNow().Unix()
	in := cap.Issuance{
		Kind:        uint32(p.Kind),
		Target:      p.Target,
		Holder:      p.Holder,
		Permissions: p.Permissions,
		Parent:      [32]byte{}, // root
		IssuedAt:    now,
		ExpiresAt:   p.ExpiresAt,
		Caveats:     caveats,
	}
	return cap.Issue(in, iss.Signer)
}

// helperContext flags whether the caveat-build helper is running for
// Issue (root cap, no parent to inherit from) or Attenuate (child cap,
// parent's caveats already in the chain).
type helperContext struct {
	forAttenuation bool
}

// buildHelperCaveats composes the wire-shape Caveats slice from
// IssueParams' typed fields. Order is stable across calls so cap bytes
// are reproducible given identical params + a deterministic signer.
//
// Caveat values are encoded per capabilities_kinds.md.
func buildHelperCaveats(p IssueParams, ctx helperContext) ([]cap.Caveat, error) {
	// First pass: scan ExtraCaveats for collisions with helper-managed
	// kinds. We do this even for Attenuate so the contract is consistent.
	seen := map[cap.CaveatKind]bool{}
	if p.Audience != ([32]byte{}) {
		seen[cap.CaveatAudience] = true
	}
	if p.NotBefore != 0 {
		// CaveatNotBefore is not in v1.0 capabilities_kinds.md; until
		// the wire spec allocates a kind for it, we cannot encode it.
		// Refuse early rather than silently dropping the field.
		return nil, errors.New("capauth: NotBefore not yet wire-allocated (pending zap-spec v1.1)")
	}
	if p.ExpiresAt != 0 {
		seen[cap.CaveatExpiresAt] = true
	}
	if p.MaxDepth != 0 {
		seen[cap.CaveatMaxDepth] = true
	}
	for _, ex := range p.ExtraCaveats {
		if seen[ex.Kind] {
			return nil, ErrCaveatDuplicate
		}
	}
	_ = ctx // currently identical for root + child; reserved for future

	// Second pass: emit helper-managed caveats first, in a stable order,
	// then append ExtraCaveats unchanged.
	out := make([]cap.Caveat, 0, len(p.ExtraCaveats)+3)
	if p.Audience != ([32]byte{}) {
		out = append(out, cap.Caveat{
			Kind:  cap.CaveatAudience,
			Value: append([]byte(nil), p.Audience[:]...),
		})
	}
	if p.ExpiresAt != 0 {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(p.ExpiresAt))
		out = append(out, cap.Caveat{
			Kind:  cap.CaveatExpiresAt,
			Value: buf[:],
		})
	}
	if p.MaxDepth != 0 {
		out = append(out, cap.Caveat{
			Kind:  cap.CaveatMaxDepth,
			Value: []byte{p.MaxDepth},
		})
	}
	out = append(out, p.ExtraCaveats...)
	return out, nil
}

// expiryFromCaveats reads the first CaveatExpiresAt's u64 LE value out of
// the supplied caveats. Returns 0 if no such caveat is present.
//
// Verify uses this to harden the chain check: the cap's ExpiresAt field
// is the fast-path expiry; a CaveatExpiresAt is a per-caveat expiry that
// the chain-AND walk respects. The two MAY disagree (the caveat MAY
// tighten the cap's own ExpiresAt); the verifier MUST honour the tighter
// of the two.
func expiryFromCaveats(caveats []cap.Caveat) (uint64, bool) {
	for _, c := range caveats {
		if c.Kind == cap.CaveatExpiresAt && len(c.Value) == 8 {
			return binary.LittleEndian.Uint64(c.Value), true
		}
	}
	return 0, false
}

// audienceFromCaveats returns the 32-byte audience hash from the first
// CaveatAudience entry in caveats, or the zero hash + false if absent.
func audienceFromCaveats(caveats []cap.Caveat) ([32]byte, bool) {
	for _, c := range caveats {
		if c.Kind == cap.CaveatAudience && len(c.Value) == 32 {
			var out [32]byte
			copy(out[:], c.Value)
			return out, true
		}
	}
	return [32]byte{}, false
}

// maxDepthFromCaveats returns the depth budget from the first
// CaveatMaxDepth in caveats, or 0 + false if absent. The depth field is
// a single byte; 0 is reserved as "absent" so a value-zero caveat
// (meaning "no further attenuations") is encoded as 1 with the
// understanding that 1 means "one more hop is permitted".
//
// We deliberately keep ChainDepthMax as the package-level hard ceiling
// independent of any caveat; the caveat is the issuer's preferred ceiling.
func maxDepthFromCaveats(caveats []cap.Caveat) (uint8, bool) {
	for _, c := range caveats {
		if c.Kind == cap.CaveatMaxDepth && len(c.Value) == 1 {
			return c.Value[0], true
		}
	}
	return 0, false
}

// _ unused-suppression sentinel for the time import.
var _ = time.Time{}

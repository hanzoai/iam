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

	"github.com/zap-proto/go/cap"
)

// Revoke produces a signed cap.Revocation record for the supplied cap.
// The Issuer's Signer MUST be the cap's original issuer (cap.Revoke
// enforces this and returns ErrChainBroken otherwise).
//
// The returned Revocation is the on-the-wire record. Callers SHOULD
// also call store.Revoke(rev.CapID) to make the revocation effective at
// THIS verifier, then publish the encoded bytes (via cap.EncodeRevocation)
// to the IAM revocation log so peers learn about it.
//
// Two-phase contract:
//
//  1. Local: store.Revoke(capID) — the local verifier immediately
//     rejects further presentations of that cap.
//  2. Global: encoded revocation gossiped to peers via the IAM
//     PubSub topic, which then call store.Revoke on their side.
//
// Step 1 is synchronous; step 2 is eventually-consistent. The CAP_MIGRATION
// non-negotiable "revocation must propagate globally within 5 seconds" is
// the SLO on step 2; this package's contribution is making step 1 atomic
// at each verifier.
func (iss *Issuer) Revoke(c cap.Cap, store RevocationStore) (cap.Revocation, error) {
	if iss == nil || iss.Signer == nil {
		return cap.Revocation{}, errors.New("capauth: Revoke called on nil Issuer or nil Signer")
	}
	if iss.Scheme == SchemeMLDSA65 {
		// The revocation record itself carries a 96-byte sig footer
		// (same as the cap). Refuse for the same wire-incompat reason.
		return cap.Revocation{}, ErrSchemeWireIncompat
	}
	now := iss.clockNow().Unix()
	rev, err := cap.Revoke(c, now, iss.Signer)
	if err != nil {
		return cap.Revocation{}, err
	}
	if store != nil {
		store.Revoke(rev.CapID)
	}
	return rev, nil
}

// ApplyRevocation parses a wire-encoded Revocation from a peer, verifies
// the RevokerSig against the cap's original Issuer pubkey, and applies
// the revocation to the local store.
//
// This is the receiving side of the gossip protocol: when an IAM replica
// publishes a Revocation, every other replica (and every resource server
// listening to the topic) calls ApplyRevocation to bring its local store
// up to date.
//
// The caller MUST supply the original issuer's public-key bytes; this
// package does not hold the inverse mapping (capID → issuer pub) since
// that's the IAM cap-store table's job. In practice the gossip message
// carries both the encoded Revocation AND the original cap's issuer hash,
// and the receiver looks up the pubkey via its IssuerRegistry.
func ApplyRevocation(encoded []byte, issuerPub []byte, store RevocationStore) error {
	rev, err := cap.DecodeRevocation(encoded)
	if err != nil {
		return err
	}
	if err := cap.VerifyRevocation(rev, issuerPub); err != nil {
		return err
	}
	if store != nil {
		store.Revoke(rev.CapID)
	}
	return nil
}

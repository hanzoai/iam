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

// Package capauth provides Hanzo IAM's ZAP capability authentication.
//
// # Layered design
//
// This package has two coherent layers stacked on top of github.com/zap-proto/go/cap:
//
//   - The library layer (this file, issue.go, attenuate.go, verify.go, revoke.go,
//     keys.go, store.go) exposes friendly verbs IAM and resource-server callers
//     use directly: Issue a root cap, Attenuate it, Verify a presented cap,
//     Revoke it, swap the Store / Clock / Signer for tests or alternate backends.
//
//   - The HTTP middleware layer (cap_auth.go) wraps the library layer for the
//     Beego controllers that today live in github.com/hanzoai/iam. It parses
//     Authorization: ZAP <b64>, stashes the verified cap on the request
//     context, and surfaces RFC 6750-style failure modes.
//
// The library layer is what every resource server (ATS, BD, TA, KMS, MPC)
// will embed. The middleware layer is IAM-flavoured (it pulls in Beego) and
// is kept out of the import surface of the library so resource servers can
// depend on capauth without dragging Beego.
//
// # Wire shape
//
// The on-the-wire token IS a ZAP-framed cap.Capability. There is no JSON
// envelope, no protobuf wrapper, no "ZCAP" magic of our own. The bytes are
// the bytes the zap-spec defines (capabilities.zap v1.0, schema FROZEN) and
// the bytes the zap-proto/go/cap runtime produces. We use base64-std for
// HTTP transport only — the bytes inside are the truth.
//
// # Schemes
//
// The cap runtime's Signer interface is fixed-size: every signature occupies
// the cap.SigSize (3408-byte) Sig footer at v1.1, with the algorithm tag at
// sig[cap.AlgTagOffset]. This package recognises two schemes today:
//
//   - Scheme 1 (Ed25519): 64-byte signature in the leading bytes of the
//     footer, scheme tag SchemeEd25519 (0x02 on the wire to align with
//     capabilities_kinds.md "Wire schemes" Ed25519 row). The bootstrap
//     scheme. Identity.sol's claim.scheme=1 maps here.
//
//   - Scheme 2 (ML-DSA-65): full FIPS 204 §5.2 Level-3 signature
//     (3309 bytes) in the leading bytes of the 3408-byte footer, scheme
//     tag SchemeMLDSA65 (0x03). The production PQ scheme. Hanzo IAM
//     signs caps with this once a Hanzo KMS key reference is wired in
//     via LoadMLDSA65FromKMS. Identity.sol's claim.scheme=2 maps here.
//
// ErrSchemeWireIncompat is retained as the sentinel error a future
// scheme (e.g. SLH-DSA-SHA2-256s at ~49 KB) would surface if its
// signature does not fit cap.SigSize. It is no longer raised by the
// in-tree ML-DSA-65 path.
//
// # Threat model boundary
//
// This package handles cap minting, attenuation, presentation, and verification.
// It does NOT handle:
//
//   - Holder proof-of-possession (DPoP-style binding). v1 ships without the
//     out-of-band holderSig over a session nonce that the zap-spec describes
//     in §2.3 step 1. Resource servers that want PoP MUST layer it on top
//     of this package (e.g. via a CaveatBearerKey allocation in zap-spec v1.1).
//     Until then, possession of the cap bytes is the access proof — this is
//     a known regression versus the spec's full §2.3, called out so it can be
//     closed in a follow-up.
//
//   - Third-party caveats (zcap-ld §3 discharge tokens). Only first-party
//     caveats in capabilities_kinds.md are honoured.
//
//   - Cap rotation policy. The package issues caps; IAM decides when to
//     rotate them.
//
// # Concurrency
//
// Issuer, Verifier, and Store implementations are safe for concurrent use.
// The Clock interface is read-only and trivially safe.
package capauth

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/zap-proto/go/cap"
)

// ChainDepthMax bounds the cap chain a Verifier will walk. The cap runtime
// itself does not impose a depth limit; we layer one here because every
// added link costs O(verify) crypto and unbounded chains are a DoS vector.
// 8 is comfortably more than any legitimate IAM → org-admin → service →
// instance → operation chain we have today.
const ChainDepthMax = 8

// Scheme identifies the signature algorithm a cap uses. Aliased to the
// runtime's cap.Scheme so there is exactly one source of truth: the
// numeric values here are the bytes written at sig[cap.AlgTagOffset]
// and the bytes the verifier dispatches on. Identity.sol's
// claim.scheme integers are deliberately NOT aligned with these values
// (claim.scheme=1 → Ed25519 / claim.scheme=2 → ML-DSA-65 in the smart
// contract namespace); callers that need to map between the two
// surfaces do so explicitly at the boundary.
type Scheme = cap.Scheme

// Scheme constants are re-exported from the cap runtime so consumers of
// this package see capauth.SchemeEd25519 without a separate import.
const (
	// SchemeEd25519 is the bootstrap scheme: 64-byte signature in the
	// leading bytes of the cap.SigSize (3408-byte) footer, scheme tag
	// 0x02 at cap.AlgTagOffset.
	SchemeEd25519 = cap.SchemeEd25519

	// SchemeMLDSA65 is the FIPS 204 Level-3 PQ scheme: 3309-byte
	// signature in the leading bytes of the cap.SigSize footer, scheme
	// tag 0x03 at cap.AlgTagOffset. Live at v1.1 of the ZAP wire spec
	// (zap-proto/go v1.1.0+).
	SchemeMLDSA65 = cap.SchemeMLDSA65
)

// Errors specific to the library layer. The runtime-level errors
// (cap.ErrExpired, cap.ErrRevoked, cap.ErrSigMismatch, …) flow through
// unchanged; the errors here name failure modes the runtime doesn't
// already have a sentinel for.
var (
	// ErrSchemeWireIncompat indicates the requested signing scheme does
	// not fit the cap.SigSize wire footer. With sig96 → sig3408 (v1.1),
	// Ed25519 and ML-DSA-65 both fit; this sentinel remains the named
	// failure mode any future scheme (e.g. SLH-DSA, ~49 KB) MUST raise
	// rather than truncating-and-corrupting a signature.
	ErrSchemeWireIncompat = errors.New("capauth: scheme is wire-incompatible with cap.SigSize")

	// ErrChainTooDeep indicates the presented cap chain exceeds
	// ChainDepthMax. Returned by Verify on a too-long chain.
	ErrChainTooDeep = errors.New("capauth: cap chain exceeds depth limit")

	// ErrAudienceMismatch indicates the cap carries a CaveatAudience that
	// does not name the resource server doing the verification.
	ErrAudienceMismatch = errors.New("capauth: audience caveat does not match verifier identity")

	// ErrCaveatWidened indicates an attempted attenuation tried to add a
	// caveat that would relax (rather than tighten) a parent constraint.
	// This is impossible to express in the wire format — a child can only
	// add caveats, never remove parent ones — but the helper-side
	// Attenuate refuses the call early to give callers a friendly error
	// instead of "verification fails later for opaque reasons".
	ErrCaveatWidened = errors.New("capauth: attenuation would widen a parent caveat")

	// ErrCaveatUnknown indicates a caveat kind not in capabilities_kinds.md.
	// Verifiers fail-closed on unknown caveats per SPEC.md §2.3 step 4.
	ErrCaveatUnknown = errors.New("capauth: unknown caveat kind")

	// ErrPermsWidened is the helper-side mirror of cap.ErrPermsExceedPar:
	// surfaced at Attenuate time so callers learn at mint-time, not later
	// at verify-time, that they tried to grant a child more than they had.
	ErrPermsWidened = errors.New("capauth: attenuation would widen parent permissions")
)

// Clock abstracts the time source for verification. Production passes
// SystemClock; tests pass a fixed clock so expiry edges are deterministic.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock backed by time.Now().
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }

// FixedClock is a Clock that returns the same instant every call. Test-only.
type FixedClock struct{ T time.Time }

// Now returns the fixed instant.
func (f FixedClock) Now() time.Time { return f.T }

// Issuer assembles caps. The fields here are the static configuration of a
// minting identity (signer + scheme + clock); per-cap parameters are passed
// to Issue/Attenuate. Multiple Issuers may coexist (e.g. per-org IAM identity).
type Issuer struct {
	// Signer is the cap.Signer that signs minted caps. Required.
	Signer cap.Signer
	// Scheme is the algorithm tag advertised in the cap.SigSize footer
	// (at byte cap.AlgTagOffset). The cap runtime writes the tag inside
	// the Signer.Sign call so the wire layer and the Issuer's typed
	// notion stay aligned: cap-aware callers can read back "what scheme
	// did this cap use" without re-parsing the signed bytes.
	Scheme Scheme
	// Clock supplies IssuedAt timestamps; defaults to SystemClock if nil.
	Clock Clock
}

// clockNow returns the issuer's clock-now in Unix seconds, defaulting to
// time.Now if no Clock is set.
func (i *Issuer) clockNow() time.Time {
	if i.Clock == nil {
		return time.Now()
	}
	return i.Clock.Now()
}

// errIssuerUnknown is the package-internal alias for cap.ErrIssuerUnknown.
// MemoryRegistry returns it on lookup misses so the cap runtime's Verifier
// sees the exact sentinel it dispatches on.
var errIssuerUnknown = cap.ErrIssuerUnknown

// bytesEqualConstantTime compares two byte slices in constant time. Used
// by IssuerRegistry.Register to detect hash collisions without leaking
// timing about the in-memory key bytes, and by verify.go where caveat
// audience IDs are compared against the verifier's resource identity.
func bytesEqualConstantTime(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

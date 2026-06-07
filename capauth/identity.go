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

// identity.go — IdentityCtx is what the resource-server middleware hands
// the handler after a successful Verify. We define it in the library
// package so handlers across services agree on the type and don't need
// to import the http middleware subpackage just for the struct.

package capauth

// IdentityCtx is the verified identity attached to a request after the
// middleware accepts a cap.
//
// The struct is intentionally small and concrete. We do NOT pass the raw
// cap.Cap here — that's available via a separate context key in the
// middleware package for handlers that need attenuation. Most handlers
// only need to know "who is this" and "what may they do", and that's
// PrincipalHex + ScopesBits.
type IdentityCtx struct {
	// PrincipalHex is the lowercase-hex Hash32 of the holder pubkey
	// (or, in v1, the userID hash when the controller bound to the
	// signed-in principal instead of a device pubkey). Suitable for
	// logging, audit trails, and "who am I" responses.
	PrincipalHex string

	// ScopesBits is the cap's Permissions field. Handlers that need to
	// enforce per-route gating beyond what the middleware checked
	// inspect this bitmask.
	ScopesBits uint64

	// CapKind is the cap.CapKind the holder presented. Useful for
	// branching: a KindIAMSession cap shouldn't be doing KindKMSSign work.
	CapKind uint32

	// ChainDepth is len(chain)+1. v1 only accepts root caps (chain
	// length 0) so this is always 1 today; the field is present for
	// the day we allow attenuated caps at the edge.
	ChainDepth int

	// CapID is the cap's ID() — the SHA-256 of the wire bytes. Audit
	// trails MUST log this; on revocation it's the index key.
	CapID [32]byte
}

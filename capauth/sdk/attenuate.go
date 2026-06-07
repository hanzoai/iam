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

// Package sdk is the convenience layer SDK consumers use to attenuate a
// cap they hold, without touching cap.Attenuate directly or threading an
// Issuer through their call sites.
//
// The library-layer Attenuate (capauth.Issuer.Attenuate) is the canonical
// surface; this package exposes a one-call shim that takes the cap as a
// base64-std string (the form clients hold), constructs the implicit
// Issuer/Signer pair the cap chain requires, and returns the attenuated
// cap as base64-std.
//
// Why one-call: SDK consumers (the client-side workflow that says "give
// me a cap that's narrower than the one I just got from IAM, then send it
// to the resource server") shouldn't need to reconstruct the
// Issuer/Signer/Clock plumbing the library layer requires. This package
// builds those once, on the caller's behalf.
//
// We deliberately publish this under `hanzo/iam/capauth/sdk/` rather than
// extending `lux/sdk/` directly: capauth is a Hanzo identity primitive,
// and pulling it sideways into Lux would invert the dep direction. Both
// the Lux SDK and any other Go consumer can vendor this package as a
// regular Go import.
package sdk

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/iam/capauth"
	zapcap "github.com/zap-proto/go/cap"
)

// AttenuateInput is the one-call shape for SDK consumers. Fields are
// optional unless noted.
//
// The caller MUST supply Cap, the parent's wire bytes (base64-std), and
// a Signer that is the cap's current Holder's private key. The cap
// runtime enforces signer.Public() == parent.Holder(); a mismatch is
// rejected.
type AttenuateInput struct {
	// Cap is the parent cap as base64-std-encoded ZAP wire bytes — the
	// form an SDK consumer holds after a /v1/iam/cap/issue or after a
	// previous Attenuate call. Required.
	Cap string

	// Signer is the cap.Signer corresponding to the parent's Holder
	// pubkey. The cap runtime enforces this binding. The SDK keeps a
	// pre-built Signer (typically an Ed25519Signer over a device key);
	// the convenience here is that the caller doesn't have to wrap it
	// in an Issuer.
	//
	// We accept the library-layer Ed25519Signer concrete type rather
	// than the cap.Signer interface to keep the surface narrow; if a
	// caller has a non-Ed25519 signer they can drop down to
	// capauth.Issuer.Attenuate directly.
	Signer *capauth.Ed25519Signer

	// NewHolder is the 32-byte hash of the child cap's Holder. The
	// SDK helper does NOT generate a fresh keypair on the caller's
	// behalf — that's the caller's threat-model decision. If the caller
	// wants to bind the child to a different device key, they pass
	// Hash32(devicePub) here. If they want to keep the parent's
	// holder (a no-op attenuation that just narrows scopes/expiry),
	// they pass the parent's Holder.
	NewHolder [32]byte

	// Scopes is the narrowed permission bitmask. MUST be a subset of
	// the parent's; the library-layer Attenuate refuses on widen.
	Scopes uint64

	// AudienceHash, if non-zero, narrows the child to a specific
	// audience. MUST equal the parent's audience or be a fresh narrowing
	// when the parent did not carry one. v1 enforces strict equality
	// when the parent already has an audience.
	AudienceHash [32]byte

	// ExpiresAt, if set, is the child's expiry. MUST be ≤ parent's.
	// Zero means "inherit parent's expiry".
	ExpiresAt time.Time

	// MaxDepth, if set, is the child's remaining-hops budget. 0 means
	// "inherit (parent's - 1)".
	MaxDepth uint8
}

// AttenuateOutput is the one-call output.
type AttenuateOutput struct {
	// Cap is the attenuated cap as base64-std-encoded ZAP wire bytes —
	// the form to put on Authorization: Cap <…> for the next request.
	Cap string

	// CapIDHex is the hex-encoded 32-byte cap ID. Useful for SDK-side
	// logging and for /v1/iam/cap/revoke later.
	CapIDHex string

	// ExpiresAt is the (possibly parent-floored) expiry of the
	// attenuated cap, as RFC3339 UTC. Clients use this for token-
	// refresh scheduling.
	ExpiresAt string
}

// Attenuate is the one-call SDK helper: parse the parent cap, attenuate
// per the input, return the new wire bytes.
//
// Errors are wrapped with the library-layer sentinel where applicable
// so callers can errors.Is(…, capauth.ErrPermsWidened) etc. without
// reaching into the cap runtime.
func Attenuate(in AttenuateInput) (AttenuateOutput, error) {
	if in.Cap == "" {
		return AttenuateOutput{}, errors.New("capauth/sdk: Cap is required")
	}
	if in.Signer == nil {
		return AttenuateOutput{}, errors.New("capauth/sdk: Signer is required")
	}
	if in.Scopes == 0 {
		return AttenuateOutput{}, errors.New("capauth/sdk: Scopes is required (zero means deny-all)")
	}

	raw, err := base64.StdEncoding.DecodeString(in.Cap)
	if err != nil {
		// Try raw-std (some HTTP libs strip '=').
		raw2, err2 := base64.RawStdEncoding.DecodeString(in.Cap)
		if err2 != nil {
			return AttenuateOutput{}, fmt.Errorf(
				"capauth/sdk: parent cap is not valid base64: %w", err)
		}
		raw = raw2
	}

	parent, err := zapcap.Wrap(raw)
	if err != nil {
		return AttenuateOutput{}, fmt.Errorf(
			"capauth/sdk: parent cap is not a valid ZAP capability: %w", err)
	}

	// Build the implicit Issuer. The signer's Public() must equal
	// parent.Holder() — cap.Attenuate enforces this; surface a friendly
	// error here too so the caller knows BEFORE we hit the cap layer.
	if in.Signer.Public() != parent.Holder() {
		return AttenuateOutput{}, errors.New(
			"capauth/sdk: Signer.Public() != parent.Holder() — wrong key for this cap")
	}

	iss := &capauth.Issuer{
		Signer: in.Signer,
		Scheme: capauth.SchemeEd25519,
		Clock:  capauth.SystemClock{},
	}

	params := capauth.AttenuateParams{
		NewHolder:   in.NewHolder,
		Permissions: in.Scopes,
		Audience:    in.AudienceHash,
		MaxDepth:    in.MaxDepth,
	}
	if !in.ExpiresAt.IsZero() {
		params.ExpiresAt = in.ExpiresAt.Unix()
	}

	child, err := iss.Attenuate(parent, params)
	if err != nil {
		// Library-layer errors are pass-through: callers errors.Is(…,
		// capauth.ErrPermsWidened) etc. work directly.
		return AttenuateOutput{}, err
	}

	id := child.ID()
	out := AttenuateOutput{
		Cap:      base64.StdEncoding.EncodeToString(child.Bytes()),
		CapIDHex: capauth.Hex32(id),
	}
	if exp := child.ExpiresAt(); exp != 0 {
		out.ExpiresAt = time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
	}
	return out, nil
}

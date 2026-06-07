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

// Package capauth wires ZAP object-capability authentication into the IAM
// HTTP surface. First production use of the cap model — replaces bearer-JWT
// auth on /v1/iam/whoami (and follow-on endpoints) with typed, attenuable,
// revocable caps.
//
// It lives outside the routers and controllers packages so both can depend on
// it without forming a cycle (routers already imports controllers).
//
// Wire shape:
//
//	Authorization: ZAP <base64-of-Capability-bytes>
//
// The bytes inside are the canonical Capability wire format from
// github.com/zap-proto/zap-spec. They are validated by cap.Wrap +
// (cap.Verifier).Verify — this package never reimplements verification.
package capauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/beego/v2/server/web/context"
	"github.com/zap-proto/go/cap"
)

// Context keys used to hand off a verified cap to controllers.
// Reads come back through ctx.Input.GetData(key) on the controller side.
const (
	// CtxKeyCap stashes the verified cap.Cap so the controller can surface
	// caveats, expiry, permissions without re-parsing.
	CtxKeyCap = "zapCap"

	// CtxKeyHolderHex stashes hex-encoded Cap.Holder() — the principal the
	// whoami endpoint returns.
	CtxKeyHolderHex = "zapHolderHex"

	// CtxKeyKind stashes the cap kind so the controller can branch on
	// IAMSession vs ServiceToken etc. without poking the cap directly.
	CtxKeyKind = "zapKind"
)

// Errors specific to the ZAP path. Distinct from the cap package errors so
// HTTP responses can map them to RFC 6750–style WWW-Authenticate values.
var (
	ErrNoZAPHeader = errors.New("zap: no Authorization: ZAP header")
	ErrBadBase64   = errors.New("zap: header value is not valid base64")
	ErrWrongKind   = errors.New("zap: cap kind does not match endpoint")
)

// ParseHeader pulls an Authorization: ZAP <b64> header off the request and
// returns the decoded bytes. Returns ErrNoZAPHeader if the header is absent
// or uses a different scheme — the caller can then fall back to Bearer.
func ParseHeader(ctx *context.Context) ([]byte, error) {
	auth := ctx.Input.Header("Authorization")
	if auth == "" {
		return nil, ErrNoZAPHeader
	}
	const prefix = "ZAP "
	if !strings.HasPrefix(auth, prefix) {
		return nil, ErrNoZAPHeader
	}
	raw := strings.TrimSpace(auth[len(prefix):])
	if raw == "" {
		return nil, ErrBadBase64
	}
	// std encoding is the canonical wire — caps are not URL-safe by default
	// because the only place they ride on the wire is inside an HTTP header,
	// where '+' and '/' are legal.
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Be permissive with padding-trimmed forms; some HTTP libraries
		// strip '=' chars in transit.
		b2, err2 := base64.RawStdEncoding.DecodeString(raw)
		if err2 != nil {
			return nil, ErrBadBase64
		}
		b = b2
	}
	return b, nil
}

// --- in-memory IAM revocation store and issuer registry --------------------

// revocations is the prototype in-memory revocation list. Production reads
// from the IAM cap-store table (LP-XXX revocation log gossiped via PubSub);
// this map is the lab-scale stand-in.
//
// The shape matches cap.Verifier.IsRevoked: cap ID -> presence => revoked.
var (
	revocationsMu sync.RWMutex
	revocations   = map[[32]byte]struct{}{}
)

// Revoke marks a cap as revoked. Idempotent.
func Revoke(capID [32]byte) {
	revocationsMu.Lock()
	defer revocationsMu.Unlock()
	revocations[capID] = struct{}{}
}

// ClearRevocations resets the in-memory list. Test-only.
func ClearRevocations() {
	revocationsMu.Lock()
	defer revocationsMu.Unlock()
	revocations = map[[32]byte]struct{}{}
}

func isRevoked(capID [32]byte) bool {
	revocationsMu.RLock()
	defer revocationsMu.RUnlock()
	_, ok := revocations[capID]
	return ok
}

// issuerRegistry resolves issuer-hash -> raw pubkey bytes. Production will
// query the IAM key registry (which itself is backed by IAM's signing-key
// table). The prototype only holds the in-memory ed25519 test keys
// registered at boot or test setup time.
var (
	issuerRegistryMu sync.RWMutex
	issuerRegistry   = map[[32]byte][]byte{}
)

// RegisterIssuer adds an issuer pubkey to the in-memory registry. hash MUST
// be cap.Hash32(pub) — i.e., SHA-256 of the raw 32-byte ed25519 pubkey. The
// cap package's Hash32 is the canonical hash function.
func RegisterIssuer(hash [32]byte, pub ed25519.PublicKey) {
	issuerRegistryMu.Lock()
	defer issuerRegistryMu.Unlock()
	// Defensive copy — caller may reuse the slice.
	cp := make([]byte, len(pub))
	copy(cp, pub)
	issuerRegistry[hash] = cp
}

// ClearIssuers wipes the in-memory issuer registry. Test-only.
func ClearIssuers() {
	issuerRegistryMu.Lock()
	defer issuerRegistryMu.Unlock()
	issuerRegistry = map[[32]byte][]byte{}
}

func issuerKey(hash [32]byte) ([]byte, error) {
	issuerRegistryMu.RLock()
	defer issuerRegistryMu.RUnlock()
	pub, ok := issuerRegistry[hash]
	if !ok {
		return nil, cap.ErrIssuerUnknown
	}
	return pub, nil
}

// verifier is the shared cap.Verifier for the IAM surface. It wires the
// in-memory revocation/issuer lookups above; production swaps these for
// IAM-table-backed implementations without changing this surface.
//
// Built once and reused — Verifier is a struct of two function pointers, so
// allocation is cheap, but keeping a singleton makes the per-request path
// explicit.
var verifier = cap.Verifier{
	IsRevoked: isRevoked,
	IssuerKey: issuerKey,
}

// Verify is the canonical entry point: parse + wrap + verify + kind check,
// then stash holder/kind on the Beego context for the controller. Returns
// nil on success; on any failure the request is unauthenticated and the
// caller writes a 401 with WWW-Authenticate: ZAP error="<code>".
func Verify(ctx *context.Context, expectKind cap.CapKind) error {
	raw, err := ParseHeader(ctx)
	if err != nil {
		return err
	}
	c, err := cap.Wrap(raw)
	if err != nil {
		return err
	}
	if cap.CapKind(c.Kind()) != expectKind {
		return ErrWrongKind
	}
	if err := verifier.Verify(c, time.Now().Unix()); err != nil {
		return err
	}
	// Stash for the controller.
	holder := c.Holder()
	ctx.Input.SetData(CtxKeyCap, c)
	ctx.Input.SetData(CtxKeyKind, uint32(c.Kind()))
	ctx.Input.SetData(CtxKeyHolderHex, hex32(holder))
	return nil
}

// HasHeader reports whether the request carries an Authorization: ZAP
// header. Used by /v1/iam/whoami to decide whether to dispatch on the cap
// path or fall through to the legacy JWT path.
func HasHeader(ctx *context.Context) bool {
	return strings.HasPrefix(ctx.Input.Header("Authorization"), "ZAP ")
}

// hex32 renders a 32-byte hash as 64-char lowercase hex without pulling in
// encoding/hex (one fewer import; the cost is one tiny function).
func hex32(h [32]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

// Hex32 is the exported form of hex32 — callers (controllers) need it to
// render Issuer hashes onto the wire alongside the holder hex.
func Hex32(h [32]byte) string { return hex32(h) }

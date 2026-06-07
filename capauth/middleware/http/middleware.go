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

// Package http provides the resource-server middleware. Wraps an
// http.Handler in cap verification: read Authorization: Cap <b64>, decode,
// run capauth.Verifier.Verify against the static config, inject the
// verified identity onto the request context.
//
// Audience naming: "<service>.<env>.<domain>", hashed to 32 bytes via
// cap.Hash32 before becoming the Verifier's Identity field. Resource
// servers compute the hash once at boot.
//
// Scope naming: "<service>:<resource>:<action>", mapped to a 64-bit
// permission bitmask via the same scopeBit table the IAM controller uses
// (each service exports its own subset of the table — there's one
// canonical mapping per kind, in capabilities_kinds.md). The middleware
// caller supplies the required-bitmask as a uint64, not a scope string,
// because the bit math is the only thing the verifier knows.
//
// Error envelope: failures write a tight JSON envelope. The cap itself is
// binary on the wire (Authorization: Cap <b64>); the error JSON is the
// HTTP-edge response. No /api/ prefix, no v2 — one canonical surface.
package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hanzoai/iam/capauth"
	zapcap "github.com/zap-proto/go/cap"
)

// contextKey is unexported so other packages can't accidentally collide
// with our context-key namespace. Mirrors net/http.contextKey style.
type contextKey struct{ name string }

var (
	// IdentityContextKey is the request-context key under which the
	// middleware stashes the verified Identity. Handlers read it with
	// `idt, ok := r.Context().Value(IdentityContextKey).(*capauth.Identity)`.
	IdentityContextKey = &contextKey{name: "capauth.Identity"}
)

// Identity is what the middleware hands the handler after a successful
// verification. The principal is the holder hex; scopes is the resolved
// permission bitmask plus the original scope strings (passed through);
// chain depth is len(chain)+1, useful for logging.
//
// Importantly, this is the IDENTITY of the caller — not the cap itself.
// Handlers that need cap-typed fields (the cap.Cap, e.g., to attenuate
// before calling downstream) can pull the cap from the context too via
// CapContextKey.
type Identity = capauth.IdentityCtx

// CapContextKey stashes the raw cap.Cap for handlers that need cap-typed
// fields (Audience, Caveats, etc.).
var CapContextKey = &contextKey{name: "capauth.Cap"}

// Config drives the middleware. All fields are required.
type Config struct {
	// Verifier is the configured cap.Verifier. Build with
	// capauth.LibVerifier{Store, Registry, Clock, Identity} once at boot.
	// MUST set Identity to cap.Hash32([]byte(<service.env.domain>)) so
	// the audience check is meaningful.
	Verifier *capauth.LibVerifier

	// AudienceHash is the hash of the resource-server's audience identifier.
	// Identical to Verifier.Identity but kept on the Config for symmetry
	// with the params the caller is passing in.
	AudienceHash [32]byte

	// RequiredScopeBits is the permission bitmask the request requires.
	// Bits are derived from the canonical scope->bit table in the
	// capabilities_kinds.md spec; the resource server is expected to know
	// which bits map to which routes (per-route gating is the caller's job
	// — this middleware checks one bitmask for all routes it wraps).
	RequiredScopeBits uint64

	// RequiredOp, if set, is an alternate way to express the required
	// bits — semantically the same as RequiredScopeBits; named so handlers
	// can be expressive about "what operation is this caller about to
	// perform". The middleware ORs the two; either source of bits counts.
	RequiredOp uint64

	// ErrorWriter, if set, overrides the default JSON error writer. The
	// default writes a tight {"error","error_description"} envelope and
	// sets WWW-Authenticate on 401.
	ErrorWriter func(w http.ResponseWriter, r *http.Request, status int, code, desc string)
}

// errEnvelope is the JSON shape written to the wire on a 401/403.
type errEnvelope struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// defaultErrorWriter writes an RFC 6750–style JSON envelope.
func defaultErrorWriter(w http.ResponseWriter, _ *http.Request, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate",
			`Cap error="`+code+`", error_description="`+desc+`"`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errEnvelope{
		Error:            code,
		ErrorDescription: desc,
	})
}

// errorOr returns the configured error writer or the default.
func (c Config) errorOr() func(http.ResponseWriter, *http.Request, int, string, string) {
	if c.ErrorWriter != nil {
		return c.ErrorWriter
	}
	return defaultErrorWriter
}

// Middleware returns an http.Handler middleware that verifies an
// Authorization: Cap <base64> header against the supplied Verifier
// configuration before calling next.
//
// On success: the verified cap.Cap and an *Identity are stashed on the
// request context (via CapContextKey and IdentityContextKey respectively)
// and next is called.
//
// On failure: a JSON error envelope is written with the appropriate status
// and next is NOT called.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.Verifier == nil {
		panic("capauth/middleware/http: Middleware called with nil Verifier")
	}
	// Compose the required-bits at construction time; per-request it's
	// the OR of both fields. Doing this once is allocation-free; pulling
	// the read into the per-request path would be one more load.
	required := cfg.RequiredScopeBits | cfg.RequiredOp
	writeErr := cfg.errorOr()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capBytes, code, desc, ok := parseHeader(r)
			if !ok {
				writeErr(w, r, http.StatusUnauthorized, code, desc)
				return
			}

			c, err := zapcap.Wrap(capBytes)
			if err != nil {
				writeErr(w, r, http.StatusUnauthorized, "invalid_token",
					"cap bytes are not a valid ZAP capability: "+err.Error())
				return
			}

			// holder check: middleware does NOT enforce holder ==
			// some-external-id because v1 has no proof-of-possession;
			// the cap is the bearer token. The Verifier still confirms
			// the cap's Holder field matches the cap's own claim of
			// holder, which is a structural check, not an external
			// binding.
			holder := c.Holder()

			if err := cfg.Verifier.Verify(capauth.VerifyParams{
				Leaf:       c,
				Chain:      nil, // v1: only root caps from /v1/iam/cap/issue
				RequiredOp: required,
				Target:     cfg.AudienceHash,
				Holder:     holder,
			}); err != nil {
				writeErr(w, r, statusForError(err), codeForError(err), err.Error())
				return
			}

			ident := &capauth.IdentityCtx{
				PrincipalHex: capauth.Hex32(holder),
				ScopesBits:   c.Permissions(),
				CapKind:      c.Kind(),
				ChainDepth:   1,
				CapID:        c.ID(),
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, IdentityContextKey, ident)
			ctx = context.WithValue(ctx, CapContextKey, c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// parseHeader pulls Authorization: Cap <b64> out of r and decodes the
// base64 to raw cap bytes. Returns (bytes, "", "", true) on success;
// (nil, code, desc, false) with WWW-Authenticate-compatible error codes
// on failure.
//
// Accepts both std and raw-std base64 (some HTTP libraries strip '=').
// Rejects everything else — no URL-safe, no MIME — because the cap rides
// in an Authorization header where '+' and '/' are legal.
func parseHeader(r *http.Request) ([]byte, string, string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, "invalid_token", "no Authorization header", false
	}
	const prefix = "Cap "
	if !strings.HasPrefix(auth, prefix) {
		// Accept legacy "ZAP " prefix as alias; the canonical IAM
		// /v1/iam/whoami endpoint emitted ZAP for the same wire shape
		// and we want zero-churn migration to "Cap".
		const altPrefix = "ZAP "
		if !strings.HasPrefix(auth, altPrefix) {
			return nil, "invalid_token",
				"Authorization scheme must be 'Cap' (Cap <base64>)", false
		}
		auth = "Cap " + auth[len(altPrefix):]
	}
	raw := strings.TrimSpace(auth[len(prefix):])
	if raw == "" {
		return nil, "invalid_token", "Authorization Cap header empty", false
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		b2, err2 := base64.RawStdEncoding.DecodeString(raw)
		if err2 != nil {
			return nil, "invalid_token",
				"Authorization Cap header is not valid base64", false
		}
		b = b2
	}
	return b, "", "", true
}

// statusForError maps a Verify error to its HTTP status code.
//
// - ErrExpired      → 401 (the cap was once valid; the holder needs a fresh one)
// - ErrRevoked      → 401 (same; IAM revoked them)
// - ErrIssuerUnknown→ 401 (the cap's issuer isn't trusted here)
// - ErrSigMismatch  → 401 (signature failure — likely tampering)
// - ErrOpNotPermitted → 403 (the principal IS authenticated; just lacks scope)
// - ErrAudienceMismatch → 403 (right principal, wrong audience)
// - everything else → 401
func statusForError(err error) int {
	switch {
	case errors.Is(err, zapcap.ErrOpNotPermitted):
		return http.StatusForbidden
	case errors.Is(err, capauth.ErrAudienceMismatch):
		return http.StatusForbidden
	case errors.Is(err, zapcap.ErrTargetMismatch):
		// Wire-level target check: same "wrong service" semantics as
		// audience mismatch, so map to 403. The caller is authenticated;
		// they're just hitting the wrong server.
		return http.StatusForbidden
	case errors.Is(err, capauth.ErrChainTooDeep):
		return http.StatusBadRequest
	}
	return http.StatusUnauthorized
}

// codeForError maps a Verify error to its RFC 6750 error code string.
func codeForError(err error) string {
	switch {
	case errors.Is(err, zapcap.ErrExpired):
		return "expired_token"
	case errors.Is(err, zapcap.ErrRevoked):
		return "revoked_token"
	case errors.Is(err, zapcap.ErrOpNotPermitted):
		return "insufficient_scope"
	case errors.Is(err, capauth.ErrAudienceMismatch),
		errors.Is(err, zapcap.ErrTargetMismatch):
		return "audience_mismatch"
	case errors.Is(err, zapcap.ErrSigMismatch):
		return "invalid_signature"
	case errors.Is(err, zapcap.ErrIssuerUnknown):
		return "untrusted_issuer"
	case errors.Is(err, capauth.ErrChainTooDeep),
		errors.Is(err, capauth.ErrCaveatUnknown),
		errors.Is(err, capauth.ErrCaveatWidened):
		return "invalid_token"
	}
	return "invalid_token"
}

// FromContext is the typed accessor handlers use to fetch the verified
// identity from a request context. Returns (nil, false) on absence so
// callers can branch on auth state explicitly.
func FromContext(ctx context.Context) (*capauth.IdentityCtx, bool) {
	v, ok := ctx.Value(IdentityContextKey).(*capauth.IdentityCtx)
	return v, ok && v != nil
}

// CapFromContext returns the raw cap.Cap stashed by the middleware. Used
// by handlers that need to attenuate the cap before calling a downstream
// service.
func CapFromContext(ctx context.Context) (zapcap.Cap, bool) {
	v, ok := ctx.Value(CapContextKey).(zapcap.Cap)
	return v, ok
}

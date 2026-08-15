// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"

	"github.com/hanzoai/orm"
)

// PasskeyOwed reports whether this identity must present a passkey to finish
// signing in. True for the reserved organization, false for everyone else.
//
// The surfaces that answer to the reserved org — the key store, the signing
// material, the cross-tenant consoles — are opened by one credential: a key held
// in the hardware of a device the person is carrying, released by their own
// biometric. A password is a shared secret. It can be read over a shoulder,
// typed into a lookalike page, or found in a dump, and none of those leave a
// mark on the account. A passkey cannot be handed to someone who is not holding
// the device, so the credential and the person travel together.
//
// It asks the SAME question [IsSuperAdmin] asks, and deliberately does not ask
// [IsReservedOrg]. Those two are different questions and the difference is the
// whole point: IsReservedOrg reads the org NAME off the request, while an
// operator is an IDENTITY that holds a membership in the reserved org and is
// usually anchored somewhere else, because operators also do ordinary work in a
// brand org. A guard written on the name lets exactly those operators — the ones
// who really exist — through.
//
// [schema.PasskeySignin] reports whether this build can CHALLENGE a passkey.
// While it cannot, this refusal is total and the reserved org has no door. That
// is the intended reading, not an oversight: the alternative — "no passkey is
// registered, so take the password" — hands the door to precisely the caller who
// has the password and not the device, which is the one this is built to stop.
// The door opens again when the assertion ceremony lands beside the credential
// rows in internal/webauthn, and it opens for a passkey.
func PasskeyOwed(ctx context.Context, db orm.DB, owner, name string) bool {
	return IsSuperAdmin(ctx, db, owner, name)
}

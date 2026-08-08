// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

// PasskeySignin reports whether a registered passkey can COMPLETE a sign-in on
// this build — the only honest reason for a login screen to draw a passkey
// button.
//
// It sits in this leaf package for the reason WalletChains does: two callers that
// must never disagree both need it, and the packages that own them cannot import
// one another (internal/webauthn -> internal/authz -> internal/oidc).
//
// internal/webauthn REGISTERS passkeys — list, get, add, update, delete over the
// webauthn_credentials rows — and holds nothing that CHALLENGES one. There is no
// assertion ceremony, so an application's EnableWebAuthn switch alone cannot be
// what a screen draws from: the switch says the org WANTS passkeys, this says the
// server can perform one. Both halves are already stated for every other method
// the login descriptor publishes (DeliveryConfigured for email/SMS codes,
// WalletChains for wallets) and this one field was left as the raw switch, so the
// descriptor advertised a passkey sign-in whose four plausible ceremony paths all
// answer 404.
//
// It stops being a constant the day the ceremony lands beside the credential rows.
func PasskeySignin() bool { return false }

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications_test

// authorizeCert gates the signing cert an application NAMES — the field that
// decides which key signs every token minted through it. A signing cert is trusted
// only under the reserved platform owners, so naming cert-hanzo is naming the key
// admin/root's own bearer is signed with. An org-admin may name a cert its own org
// owns and no other; only a SuperAdmin may name the reserved platform cert. These
// drive the REAL router (newOrgHarness seeds admin/cert-hanzo), so the Guard
// attaches a principal and the gate runs.

import "testing"

// An org-admin cannot CREATE an application that names the platform signing cert.
// This is the root of the forge chain: with no non-super app able to point at the
// trusted key, no forged admin bearer can ever be signed, so the chain never leaves
// the ground.
func TestCreate_CertGate_refusesReservedSigningCert(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "hanzo/boss")

	if st := h.do(t, "POST", "/v1/iam/applications", boss,
		`{"owner":"hanzo","name":"forge","organization":"hanzo","clientId":"forge","cert":"cert-hanzo"}`); st != 403 {
		t.Fatalf("org-admin naming the platform signing cert: status=%d, want 403", st)
	}
	// And the forged app is not there to sign anything: the create was refused
	// before it persisted.
	if st := h.do(t, "GET", "/v1/iam/applications/hanzo/forge", boss, ""); st != 404 {
		t.Fatalf("refused create must persist nothing: get status=%d, want 404", st)
	}
}

// The same gate guards Update: an org-admin cannot re-point an app it owns at the
// platform signing cert either.
func TestUpdate_CertGate_refusesReservedSigningCert(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "hanzo/boss")

	if st := h.do(t, "POST", "/v1/iam/applications", boss,
		`{"owner":"hanzo","name":"svc","organization":"hanzo","clientId":"svc"}`); st != 200 {
		t.Fatalf("seed own app: status=%d, want 200", st)
	}
	if st := h.do(t, "PUT", "/v1/iam/applications/hanzo/svc", boss,
		`{"owner":"hanzo","name":"svc","organization":"hanzo","clientId":"svc","cert":"cert-hanzo"}`); st != 403 {
		t.Fatalf("re-pointing an own app at the platform signing cert: status=%d, want 403", st)
	}
}

// A SuperAdmin is the one identity that may name the platform signing cert — the
// gate must not break the legitimate platform-app registration.
func TestCreate_CertGate_superAdminMayNameReservedCert(t *testing.T) {
	h := newOrgHarness(t)
	root := h.token(t, "admin/root")

	if st := h.do(t, "POST", "/v1/iam/applications", root,
		`{"owner":"hanzo","name":"platform","organization":"hanzo","clientId":"platform","cert":"cert-hanzo"}`); st != 200 {
		t.Fatalf("SuperAdmin naming the platform signing cert: status=%d, want 200", st)
	}
}

// A cert the reserved signing owners do not hold names no platform identity, so an
// org-admin may name it: the gate pins the platform key, it does not forbid an app
// from naming a cert of its own.
func TestCreate_CertGate_allowsNonReservedCert(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "hanzo/boss")

	if st := h.do(t, "POST", "/v1/iam/applications", boss,
		`{"owner":"hanzo","name":"ownapp","organization":"hanzo","clientId":"ownapp","cert":"cert-tenant-own"}`); st != 200 {
		t.Fatalf("org-admin naming a non-reserved cert: status=%d, want 200", st)
	}
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package webauthn_test

// A passkey authenticates its User, so REGISTERING one for a person is acting for
// that account. The write authorizes that subject the same way the list authorizes
// reading it — otherwise a caller files a credential of its own under
// User=admin/root and the public signin ceremony, which offers a person's
// credentials by User, hands it to the attacker's authenticator. These drive the
// REAL router (newRig seeds admin/cert-hanzo), so the Guard attaches a principal
// and the write's gate runs.

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// write posts one credential registration as sub and returns the status.
func (r *rig) write(t *testing.T, sub, body string) int {
	t.Helper()
	req := httptest.NewRequest("POST", keys, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.bearer(t, sub))
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (r *rig) credsFor(t *testing.T, user string) int {
	t.Helper()
	rows, err := orm.TypedQuery[schema.WebauthnCredential](r.db).Filter("User=", user).GetAll(context.Background())
	if err != nil {
		t.Fatalf("query %s: %v", user, err)
	}
	return len(rows)
}

// The passkey-plant is refused, and nothing lands under admin/root — so the signin
// ceremony that offers a person's credentials by User has none of the attacker's to
// offer.
func TestAdd_refusesAPasskeyPlantedForAReservedUser(t *testing.T) {
	r := newRig(t)
	before := r.credsFor(t, "admin/root")

	if st := r.write(t, "hanzo/boss",
		`{"owner":"hanzo","name":"plant","user":"admin/root","credentialId":"AAAA","publicKey":"AAAA","userVerified":true}`); st != 403 {
		t.Fatalf("planting a passkey for admin/root: status=%d, want 403", st)
	}
	if after := r.credsFor(t, "admin/root"); after != before {
		t.Fatalf("a credential landed under admin/root: %d -> %d", before, after)
	}
}

// The same gate refuses a plant aimed at ANOTHER tenant's user.
func TestAdd_refusesAPasskeyPlantedForAnotherTenant(t *testing.T) {
	r := newRig(t)
	if st := r.write(t, "hanzo/boss",
		`{"owner":"hanzo","name":"plant","user":"orgb/carol","credentialId":"AAAA","publicKey":"AAAA"}`); st != 403 {
		t.Fatalf("planting a passkey for orgb/carol: status=%d, want 403", st)
	}
}

// An org-admin may still register a passkey for its OWN member — the gate pins the
// subject, it does not forbid the enrollment an admin may legitimately do.
func TestAdd_allowsAPasskeyForAnOwnMember(t *testing.T) {
	r := newRig(t)
	if st := r.write(t, "hanzo/boss",
		`{"owner":"hanzo","name":"alice-newkey","user":"hanzo/alice","credentialId":"AAAA","publicKey":"AAAA"}`); st != 200 {
		t.Fatalf("registering a passkey for an own member: status=%d, want 200", st)
	}
}

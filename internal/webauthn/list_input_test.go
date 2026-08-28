// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package webauthn_test

import "testing"

// A named target is a person, spelled <organization>/<username>. Ask for one that
// is not — a bare word with no slash — and the answer is a 400 that says so,
// authenticated but unparseable, never a silent empty list that reads like "you
// have no passkeys".
func TestList_userMustBeOrgSlashName(t *testing.T) {
	r := newRig(t)

	status, _, body := r.list(t, "hanzo/alice", "?user=nogroup")
	if status != 400 {
		t.Fatalf("status=%d body=%s, want 400 for a target that is not org/name", status, body)
	}
}

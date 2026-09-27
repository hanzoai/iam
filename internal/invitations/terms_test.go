// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invitations

// An invitation is issued with a code long and plain enough to stand as the only
// thing admitting a stranger, pinned to one bare address, and never as a pattern.
// An edit that leaves an older invitation's terms as they were is not re-judged.

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

func TestCreate_refusesTermsNoInvitationMayCarry(t *testing.T) {
	h, _ := newHandler(t)
	ctx := context.Background()
	for _, in := range []Input{
		{Owner: "acme", Name: "a", Code: "acme-7f3k"},                     // 9 characters
		{Owner: "acme", Name: "b", Code: "AAAAAAAAAAAA"},                  // one character
		{Owner: "acme", Name: "c", Code: "K7PQ2M9XRT K7"},                 // a space
		{Owner: "acme", Name: "d", Code: "ACME-[0-9]{4}", IsRegexp: true}, // a pattern
		{Owner: "acme", Name: "e", Code: "K7PQ2M9XRT", Email: `"Hanzo Billing" <victim@example.com>`},
		{Owner: "acme", Name: "f", Code: "K7PQ2M9XRT", Email: "a@example.com, b@example.com"},
	} {
		if _, err := h.Create(ctx, &in); err == nil {
			t.Errorf("%s: created with code %q email %q", in.Name, in.Code, in.Email)
		} else {
			wantStatus(t, err, 400)
		}
	}
	if _, err := h.Create(ctx, &Input{Owner: "acme", Name: "ok", Code: "K7PQ2M9XRT", Email: "ada@example.com"}); err != nil {
		t.Fatalf("a sound invitation was refused: %v", err)
	}
}

func TestUpdate_keepsAnOlderInvitationEditable(t *testing.T) {
	h, db := newHandler(t)
	ctx := context.Background()
	old := orm.New[schema.Invitation](db)
	old.Owner, old.Name, old.Code, old.Quota = "acme", "legacy", "acme-7f3k", 5
	old.SetId("acme/legacy")
	if err := old.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Update(ctx, &Input{Owner: "acme", Name: "legacy", Code: "acme-7f3k", Quota: 10}); err != nil {
		t.Fatalf("an edit that keeps the code was refused: %v", err)
	}
	_, err := h.Update(ctx, &Input{Owner: "acme", Name: "legacy", Code: "short", Quota: 10})
	wantStatus(t, err, 400)
}

// A create that names no code gets one IAM mints — 20 characters of an
// unambiguous alphabet from crypto/rand — and only such a code is marked
// generated. A code a caller wrote is not, and an update that changes the code
// takes the mark away.
func TestCreate_mintsTheCodeWhenNoneIsGiven(t *testing.T) {
	h, _ := newHandler(t)
	ctx := context.Background()
	minted, err := h.Create(ctx, &Input{Owner: "acme", Name: "a", Quota: 1, State: "Active"})
	if err != nil {
		t.Fatal(err)
	}
	if !minted.Generated || len(minted.Code) != 20 || strings.Trim(minted.Code, codeAlphabet) != "" {
		t.Fatalf("minted %q generated=%v", minted.Code, minted.Generated)
	}
	other, _ := h.Create(ctx, &Input{Owner: "acme", Name: "b", Quota: 1, State: "Active"})
	if other.Code == minted.Code {
		t.Fatal("two mints gave one code")
	}
	typed, err := h.Create(ctx, &Input{Owner: "acme", Name: "c", Code: "Welcome2026", Quota: 1})
	if err != nil || typed.Generated {
		t.Fatalf("a typed code: %v generated=%v", err, typed != nil && typed.Generated)
	}
	kept, err := h.Update(ctx, &Input{Owner: "acme", Name: "a", Code: minted.Code, Quota: 5, State: "Active"})
	if err != nil || !kept.Generated {
		t.Fatalf("an edit that keeps the minted code: %v generated=%v", err, kept != nil && kept.Generated)
	}
	changed, err := h.Update(ctx, &Input{Owner: "acme", Name: "a", Code: "Welcome2027", Quota: 5, State: "Active"})
	if err != nil || changed.Generated {
		t.Fatalf("an edit that writes a code: %v generated=%v", err, changed != nil && changed.Generated)
	}
}

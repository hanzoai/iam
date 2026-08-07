// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server

import (
	"context"
	"testing"
)

type hostSender struct{ orgs []string }

func (h *hostSender) Send(_ context.Context, org, _, _, _ string) error {
	h.orgs = append(h.orgs, org)
	return nil
}

// A HOST outside this module must be able to supply the transport. The seam
// lives in an internal package, so without this re-export a grafted IAM could
// never deliver a code and every code-shaped method would stay dark in the one
// deployment that has notify in the same process.
func TestAHostCanBindDelivery(t *testing.T) {
	var s Sender = &hostSender{}
	BindSender(s)
	t.Cleanup(func() { BindSender(nil) })

	if !DeliveryConfigured() {
		t.Fatal("binding a sender did not switch delivery on")
	}
	BindSender(nil)
	if DeliveryConfigured() {
		t.Fatal("unbinding did not switch delivery off — the predicate must follow the sender")
	}
}

// PlaneSender must return an UNTYPED nil when notify is unreachable. A typed nil
// in an interface is not nil, so BindSender would hold a sender, DeliveryConfigured
// would answer true, and the login screen would offer a code it cannot send — the
// exact lie this predicate exists to prevent.
func TestPlaneSenderIsUntypedNilWithNoPeer(t *testing.T) {
	t.Setenv("ZIP_RUNTIME_DIR", t.TempDir()) // no notify socket here
	s := PlaneSender()
	if s != nil {
		t.Fatal("PlaneSender returned non-nil with no notify peer — delivery would look configured")
	}
	BindSender(s)
	t.Cleanup(func() { BindSender(nil) })
	if DeliveryConfigured() {
		t.Fatal("binding an unreachable sender reported delivery configured")
	}
}

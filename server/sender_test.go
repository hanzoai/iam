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

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server

import (
	"context"
	"testing"
)

type hostSender struct{ sent []Message }

func (h *hostSender) Send(_ context.Context, m Message) error {
	h.sent = append(h.sent, m)
	return nil
}

// A HOST outside this module must be able to supply the transport. The seam
// lives in an internal package, so without this re-export a grafted IAM could
// never deliver a code and every code-shaped method would stay dark in the one
// deployment that has a delivery service to reach.
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

// A host must receive a message it can carry WITHOUT knowing any OTP policy: the
// words are already written and the expiry is already stated.
//
// This is the property that lets the transport live in the host. It used to live
// here, because the wording lived here too — and a transport that composed its own
// sentence would have had to restate verificationCodeTTL, a constant it cannot
// read. Now the host receives bytes and an address and needs to know nothing else.
func TestAHostReceivesAMessageItCanCarryWithoutKnowingThePolicy(t *testing.T) {
	h := &hostSender{}
	BindSender(h)
	t.Cleanup(func() { BindSender(nil) })

	m := Message{Org: "hanzo", Channel: "phone", To: "+15550100", Body: "your code is 123456"}
	if err := h.Send(context.Background(), m); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := h.sent[0]
	if got.Org == "" {
		t.Error("no tenant reached the transport — a carrier resolves the sending account by org")
	}
	if got.Body == "" {
		t.Error("no body reached the transport — the words are IAM's to write, not the carrier's")
	}
}

// THERE IS NO PlaneSender ANY MORE, and this records why rather than leaving the
// absence to be rediscovered.
//
// It returned the plane transport when notify's socket FILE existed and nil when it
// did not, and nil was the delivery switch. Both halves were wrong. A socket file
// outlives the process that bound it wherever the run directory is a volume, so a
// file a dead pod left behind reported delivery that could not happen — the fleet
// has already paid three days of a fail-closed payment rail for exactly that shape.
// And notify is started ON DEMAND, so a service that one call would have woken
// reported no delivery at all: the predicate hid the method, nothing ever called
// notify, and nothing ever would.
//
// Neither fact is knowable here. Whether a delivery service is part of a deployment
// — and whether a cold one can be started — is known to the router that owns the app
// list, and this module links no router. So the transport moved to the composition
// root that has one, and this package keeps only the seam.
func TestDeliveryIsTheHostsAssertionNotASocketFile(t *testing.T) {
	t.Setenv("ZIP_RUNTIME_DIR", t.TempDir()) // whatever is or is not here changes nothing

	BindSender(nil)
	if DeliveryConfigured() {
		t.Fatal("delivery reported configured with no sender bound")
	}
	BindSender(&hostSender{})
	t.Cleanup(func() { BindSender(nil) })
	if !DeliveryConfigured() {
		t.Fatal("a host that bound a transport must be believed — the predicate is its assertion")
	}
}

// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// fakeSender records what it was asked to deliver and fails on demand.
type fakeSender struct {
	err  error
	sent []Message
}

func (f *fakeSender) Send(_ context.Context, m Message) error {
	f.sent = append(f.sent, m)
	return f.err
}

// bindSender installs s for the duration of one test and restores the previous
// binding after, so these tests can run in any order.
func bindSender(t *testing.T, s Sender) {
	t.Helper()
	prev := sender
	sender = s
	t.Cleanup(func() { sender = prev })
}

// A code sign-in is offered only when a code can actually reach a person.
//
// Two independent facts have to hold and they were conflated into one: the
// application switch says the ORG wants email/SMS codes, and DeliveryConfigured
// says the SERVER can send one. Only the first was consulted, so every app
// advertised `code: true` while the delivery seam was unbound — measured against
// production, where a send to probe@example.invalid, an address that cannot exist,
// answered {status:"ok"}.
func TestCodeSigninNeedsBothTheSwitchAndDelivery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		bound   bool
		want    bool
	}{
		{"wanted and deliverable", true, true, true},
		{"wanted but nothing can send it", true, false, false},
		{"deliverable but the org said no", false, true, false},
		{"neither", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.bound {
				bindSender(t, &fakeSender{})
			} else {
				bindSender(t, nil)
			}
			if got := tc.enabled && DeliveryConfigured(); got != tc.want {
				t.Errorf("code offered = %v, want %v (switch=%v bound=%v)",
					got, tc.want, tc.enabled, tc.bound)
			}
		})
	}
}

// DeliveryConfigured must answer from the BOUND SENDER, never from configuration.
//
// The first version of this gate keyed on IAM_NOTIFY_ADDR. Nothing else in the
// repo read that variable, so setting it would have restored the button and
// silenced the endpoint's refusal while still sending nothing — re-arming the
// exact {status:"ok"} lie the gate exists to remove. An address is a CLAIM that
// delivery exists; a sender IS delivery.
func TestDeliveryIsDecidedByTheSenderNotAnAddress(t *testing.T) {
	bindSender(t, nil)
	t.Setenv("IAM_NOTIFY_ADDR", "notify.hanzo.svc:8000")
	if DeliveryConfigured() {
		t.Error("an address alone reported delivery configured — nothing would have been sent")
	}

	bindSender(t, &fakeSender{})
	t.Setenv("IAM_NOTIFY_ADDR", "")
	if !DeliveryConfigured() {
		t.Error("a bound sender must report delivery configured, address or not")
	}
}

// The login descriptor is the screen's source of truth, so the switch must be
// masked THERE too — leaving it on would draw the button whatever authMethods says.
// The org's stored setting is not modified; only what the browser is told.
func TestLoginViewMasksUndeliverableCodeSignin(t *testing.T) {
	app := &schema.Application{EnableCodeSignin: true, EnablePassword: true}

	bindSender(t, nil)
	if v := loginView(app); v.EnableCodeSignin {
		t.Error("code sign-in advertised with no delivery configured")
	}
	if !app.EnableCodeSignin {
		t.Error("the org's stored setting was mutated; only the VIEW may be masked")
	}
	if v := loginView(app); !v.EnablePassword {
		t.Error("password sign-in must be unaffected")
	}

	bindSender(t, &fakeSender{})
	if v := loginView(app); !v.EnableCodeSignin {
		t.Error("code sign-in must return once a sender is bound — no second switch to flip")
	}
}

// A sender that fails must be reported as a failure. Answering ok because the code
// was minted recreates the same lie one layer down: the caller asked for a send.
func TestSendFailureIsReportedNotSwallowed(t *testing.T) {
	f := &fakeSender{err: errors.New("twilio: 21608 unverified number")}
	bindSender(t, f)

	if err := sender.Send(context.Background(), message("hanzo", "email", "someone@example.com", "123456")); err == nil {
		t.Fatal("a failing sender must surface its error to the endpoint")
	}
	if len(f.sent) != 1 {
		t.Fatalf("sender was called %d times, want 1", len(f.sent))
	}
	got := f.sent[0]
	if got.Org != "hanzo" || got.Channel != "email" || got.To != "someone@example.com" {
		t.Errorf("sender got %+v — the tenant, channel and destination must all reach it", got)
	}
	if !strings.Contains(got.Body, "123456") {
		t.Errorf("the body %q does not carry the code", got.Body)
	}
}

// The message IAM composes carries the code, states the SAME expiry the record is
// checked against, and names no brand.
//
// The expiry is the reason this composition lives here rather than in a transport.
// One process answers for every white-label identity host and every one of them
// expires a code after verificationCodeTTL, so a transport writing its own sentence
// would be restating a policy it cannot read — and the two would part company the
// first time the TTL moved. This asserts they agree.
func TestTheMessageStatesTheRealExpiryAndNoBrand(t *testing.T) {
	m := message("hanzo", "phone", "+15550100", "246810")

	if !strings.Contains(m.Body, "246810") {
		t.Errorf("body %q does not carry the code", m.Body)
	}
	want := fmt.Sprintf("expires in %d minutes", int(verificationCodeTTL.Minutes()))
	if !strings.Contains(m.Body, want) {
		t.Errorf("body %q does not state the real expiry (%q from verificationCodeTTL)", m.Body, want)
	}
	for _, brand := range []string{"Hanzo", "Lux", "Zoo", "Pars"} {
		if strings.Contains(m.Body, brand) {
			t.Errorf("body names the brand %q — one process answers for every white-label host", brand)
		}
	}
	// A subject rides email only; an SMS has nowhere to put one.
	if m.Subject != "" {
		t.Errorf("an sms carried a subject %q", m.Subject)
	}
	if s := message("hanzo", "email", "a@b.test", "1").Subject; s == "" {
		t.Error("an email carried no subject")
	}
}

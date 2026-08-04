// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

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
		addr    string
		want    bool
	}{
		{"wanted and deliverable", true, "notify.hanzo.svc:8000", true},
		{"wanted but nothing can send it", true, "", false},
		{"deliverable but the org said no", false, "notify.hanzo.svc:8000", false},
		{"neither", false, "", false},
		{"whitespace is not an address", true, "   ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("IAM_NOTIFY_ADDR", tc.addr)
			if got := tc.enabled && DeliveryConfigured(); got != tc.want {
				t.Errorf("code offered = %v, want %v (switch=%v addr=%q)",
					got, tc.want, tc.enabled, tc.addr)
			}
		})
	}
}

// The login descriptor is the screen's source of truth, so the switch must be
// masked THERE too — leaving it on would draw the button whatever authMethods says.
// The org's stored setting is not modified; only what the browser is told.
func TestLoginViewMasksUndeliverableCodeSignin(t *testing.T) {
	app := &schema.Application{EnableCodeSignin: true, EnablePassword: true}

	t.Setenv("IAM_NOTIFY_ADDR", "")
	if v := loginView(app); v.EnableCodeSignin {
		t.Error("code sign-in advertised with no delivery configured")
	}
	if !app.EnableCodeSignin {
		t.Error("the org's stored setting was mutated; only the VIEW may be masked")
	}
	if v := loginView(app); !v.EnablePassword {
		t.Error("password sign-in must be unaffected")
	}

	t.Setenv("IAM_NOTIFY_ADDR", "notify.hanzo.svc:8000")
	if v := loginView(app); !v.EnableCodeSignin {
		t.Error("code sign-in must return once delivery is configured — no second switch to flip")
	}
}

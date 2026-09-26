// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invitations_test

// POST /v1/iam/invitations/{owner}/{name}/send emails an invitation to the address
// it is pinned to. What it must hold: only an admin of the invitation's org sends
// it, only the pinned address receives it, the link is on a configured identity
// host whatever Host the request carried, the sending account is the platform
// application's org (a customer org has none), and one invitation is not mailed
// twice inside a minute.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// outbox is a delivery transport that keeps what it was handed.
type outbox struct {
	mu   sync.Mutex
	sent []otp.Message
	fail error
}

func (o *outbox) Send(_ context.Context, m otp.Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail != nil {
		return o.fail
	}
	o.sent = append(o.sent, m)
	return nil
}

func (o *outbox) messages() []otp.Message {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]otp.Message(nil), o.sent...)
}

// sendRig is the list harness plus the rows a send reads: the customer org acme
// with its admin and a member, the platform application every brand host signs
// in through, another tenant's application, and a delivery transport.
func sendRig(t *testing.T) (*harness, *outbox) {
	t.Helper()
	t.Setenv("IAM_ISSUER", "https://hanzo.id")
	t.Setenv("IAM_ISSUER_MAP", `{"lux.id":"https://lux.id"}`)
	if err := oidc.InitIssuerResolver(); err != nil {
		t.Fatalf("issuer: %v", err)
	}
	h := newHarness(t)
	seedUser(t, h.db, "acme", "owner", true)
	seedUser(t, h.db, "acme", "bob", false)
	seedOrgRow(t, h.db, "acme", "Acme Robotics")
	seedOrgRow(t, h.db, "globex", "Globex")
	seedAppRow(t, h.db, "admin", "hanzo-app", "hanzo")
	seedAppRow(t, h.db, "globex", "globex-app", "globex")

	box := &outbox{}
	otp.BindSender(box)
	t.Cleanup(func() { otp.BindSender(nil) })
	return h, box
}

func seedOrgRow(t *testing.T, db orm.DB, name, display string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name, o.DisplayName = "admin", name, display
	o.SetId("admin/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org %s: %v", name, err)
	}
}

func seedAppRow(t *testing.T, db orm.DB, owner, name, org string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.Organization = owner, name, org
	a.SetId(owner + "/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app %s/%s: %v", owner, name, err)
	}
}

func seedPinned(t *testing.T, db orm.DB, owner, name, email string) {
	t.Helper()
	inv := orm.New[schema.Invitation](db)
	inv.Owner, inv.Name = owner, name
	inv.Code, inv.Quota, inv.State, inv.Email = "K7PQ2M9XRT", 1, "Active", email
	inv.SetId(owner + "/" + name)
	if err := inv.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
}

// send drives one send as sub, arriving on host, and returns status and body.
func (h *harness) send(t *testing.T, sub, host, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

const (
	sendPath = "/v1/iam/invitations/acme/inv-1/send"
	platform = `{"application":"admin/hanzo-app"}`
)

func TestSend_mailsThePinnedAddressFromThePlatformOrg(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "acme", "inv-1", "ada@example.com")

	status, body := h.send(t, "acme/owner", "hanzo.id", sendPath, platform)
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var out struct {
		Sent bool   `json:"sent"`
		To   string `json:"to"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || !out.Sent || out.To != "ada@example.com" {
		t.Fatalf("answer %s", body)
	}
	got := box.messages()
	if len(got) != 1 {
		t.Fatalf("sent %d messages", len(got))
	}
	m := got[0]
	if m.To != "ada@example.com" || m.Channel != otp.Email {
		t.Fatalf("to %q over %q", m.To, m.Channel)
	}
	// acme has no sending account; the platform application's org sends.
	if m.Org != "hanzo" {
		t.Fatalf("sent as org %q, want the platform application's org hanzo", m.Org)
	}
	if !strings.Contains(m.Subject, "Acme Robotics") {
		t.Fatalf("subject %q does not name the org", m.Subject)
	}
	link := "https://hanzo.id/join?client_id=hanzo-app&invite=K7PQ2M9XRT&org=acme"
	if !strings.Contains(m.Body, link) {
		t.Fatalf("body does not carry %s:\n%s", link, m.Body)
	}
}

// The link is on a CONFIGURED identity host. The Host header selects one; it never
// becomes one.
func TestSend_linkHostIsAConfiguredIssuer(t *testing.T) {
	for host, want := range map[string]string{
		"lux.id":       "https://lux.id/join?",
		"evil.example": "https://hanzo.id/join?",
	} {
		t.Run(host, func(t *testing.T) {
			h, box := sendRig(t)
			seedPinned(t, h.db, "acme", "inv-1", "ada@example.com")
			if status, body := h.send(t, "acme/owner", host, sendPath, platform); status != 200 {
				t.Fatalf("status=%d body=%s", status, body)
			}
			if got := box.messages(); len(got) != 1 || !strings.Contains(got[0].Body, want) {
				t.Fatalf("want a link starting %s, got %+v", want, got)
			}
		})
	}
}

func TestSend_refusals(t *testing.T) {
	for _, tc := range []struct {
		name, sub, path, body string
		pin                   string
		want                  int
	}{
		{"a member who does not administer the org", "acme/bob", sendPath, platform, "ada@example.com", 403},
		{"an admin of another org", "hanzo/boss", sendPath, platform, "ada@example.com", 403},
		{"an invitation pinned to no address", "acme/owner", sendPath, platform, "", 400},
		{"no application named", "acme/owner", sendPath, `{}`, "ada@example.com", 400},
		{"another tenant's application", "acme/owner", sendPath, `{"application":"globex/globex-app"}`, "ada@example.com", 400},
		{"an application that does not exist", "acme/owner", sendPath, `{"application":"admin/nope"}`, "ada@example.com", 400},
		{"an invitation that does not exist", "acme/owner", "/v1/iam/invitations/acme/inv-9/send", platform, "ada@example.com", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, box := sendRig(t)
			seedPinned(t, h.db, "acme", "inv-1", tc.pin)
			if status, body := h.send(t, tc.sub, "hanzo.id", tc.path, tc.body); status != tc.want {
				t.Fatalf("status=%d body=%s, want %d", status, body, tc.want)
			}
			if got := box.messages(); len(got) != 0 {
				t.Fatalf("a refused send mailed %d messages", len(got))
			}
		})
	}
}

// A SuperAdmin sends for any org.
func TestSend_superAdmin(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "acme", "inv-1", "ada@example.com")
	if status, body := h.send(t, "admin/root", "hanzo.id", sendPath, platform); status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if len(box.messages()) != 1 {
		t.Fatal("nothing was sent")
	}
}

// Inside a minute the same invitation is not mailed again.
func TestSend_resendTooSoon(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "acme", "inv-1", "ada@example.com")
	if status, body := h.send(t, "acme/owner", "hanzo.id", sendPath, platform); status != 200 {
		t.Fatalf("first: status=%d body=%s", status, body)
	}
	if status, body := h.send(t, "acme/owner", "hanzo.id", sendPath, platform); status != 429 {
		t.Fatalf("second: status=%d body=%s, want 429", status, body)
	}
	if got := box.messages(); len(got) != 1 {
		t.Fatalf("mailed %d times, want once", len(got))
	}
}

// With nothing to deliver through, the send says so, and a failed send does not
// hold the next one back.
func TestSend_noDelivery(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "acme", "inv-1", "ada@example.com")
	otp.BindSender(nil)
	if status, body := h.send(t, "acme/owner", "hanzo.id", sendPath, platform); status != 503 {
		t.Fatalf("status=%d body=%s, want 503", status, body)
	}
	box.fail = errors.New("smtp down")
	otp.BindSender(box)
	if status, body := h.send(t, "acme/owner", "hanzo.id", sendPath, platform); status != 502 {
		t.Fatalf("status=%d body=%s, want 502", status, body)
	}
	box.fail = nil
	if status, body := h.send(t, "acme/owner", "hanzo.id", sendPath, platform); status != 200 {
		t.Fatalf("after the outage: status=%d body=%s, want 200", status, body)
	}
}

// A pattern is not a code; the invitation's default code is the one mailed.
func TestSend_patternSendsItsDefaultCode(t *testing.T) {
	h, box := sendRig(t)
	inv := orm.New[schema.Invitation](h.db)
	inv.Owner, inv.Name, inv.Email = "acme", "inv-1", "ada@example.com"
	inv.Code, inv.IsRegexp, inv.DefaultCode = "ACME-[0-9]{4}", true, "ACME-2026"
	inv.Quota, inv.State = 1, "Active"
	inv.SetId("acme/inv-1")
	if err := inv.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if status, body := h.send(t, "acme/owner", "hanzo.id", sendPath, platform); status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if got := box.messages(); len(got) != 1 || !strings.Contains(got[0].Body, "invite=ACME-2026") || strings.Contains(got[0].Body, "[0-9]") {
		t.Fatalf("mailed %+v", got)
	}
}

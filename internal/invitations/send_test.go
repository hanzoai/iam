// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invitations_test

// POST /v1/iam/invitations/{owner}/{name}/send emails an invitation to the address
// it is pinned to. What it must hold: only an admin of the invitation's org sends
// it; it goes out through the platform application the caller's access token was
// issued to — that application's org sends, and the link is on the token's issuer
// — and never through one the request names; only the pinned address receives it,
// written bare; a name somebody chose cannot put markup or a second link in the
// email; and one invitation, one org and one address are each paced.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// outbox is a delivery transport that keeps what it was handed. during runs while
// a message is in flight, before the answer.
type outbox struct {
	mu     sync.Mutex
	sent   []otp.Message
	fail   error
	during func()
}

func (o *outbox) Send(_ context.Context, m otp.Message) error {
	if o.during != nil {
		o.during()
	}
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

// sendRig is the list harness plus what a send reads: the customer org acme with
// its admin and a member, the platform's applications on two brands, a tenant's
// own application, and a delivery transport.
func sendRig(t *testing.T) (*harness, *outbox) {
	t.Helper()
	h := newHarness(t)
	seedUser(t, h.db, "acme", "owner", true)
	seedUser(t, h.db, "acme", "bob", false)
	seedOrgRow(t, h.db, "acme", "Acme Robotics")
	seedOrgRow(t, h.db, "globex", "Globex")
	seedAppRow(t, h.db, "hanzo-app", "hanzo", true)
	seedAppRow(t, h.db, "lux-app", "lux", true)
	seedAppRow(t, h.db, "globex-console", "globex", false)

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

// seedAppRow files an application under admin, as bootstrap files every one —
// the platform's and tenants' alike — so only Platform tells them apart.
func seedAppRow(t *testing.T, db orm.DB, name, org string, platform bool) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.Organization, a.ClientId, a.Platform = "admin", name, org, name, platform
	a.SetId("admin/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app %s: %v", name, err)
	}
}

func seedPinned(t *testing.T, db orm.DB, name, email string) {
	t.Helper()
	inv := orm.New[schema.Invitation](db)
	inv.Owner, inv.Name = "acme", name
	inv.Code, inv.Quota, inv.State, inv.Email = "K7PQ2M9XRT", 1, "Active", email
	inv.SetId("acme/" + name)
	if err := inv.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
}

// access signs an access token for sub, issued by iss to the client azp.
func (h *harness) access(t *testing.T, sub, azp, iss, kind string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub, "azp": azp, "aud": azp, "iss": iss, "tokenType": kind,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = signingKid
	s, err := tok.SignedString(h.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// send drives one send with bearer, arriving on host, and returns status and body.
func (h *harness) send(t *testing.T, bearer, host, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

const sendPath = "/v1/iam/invitations/acme/inv-1/send"

// owner is acme's admin signed in to the platform's Hanzo app at hanzo.id.
func (h *harness) owner(t *testing.T) string {
	return h.access(t, "acme/owner", "hanzo-app", "https://hanzo.id", "access-token")
}

func TestSend_mailsThePinnedAddressTheWayTheInviterCameIn(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "inv-1", "ada@example.com")

	status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`)
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
	if m.To != "ada@example.com" || m.Channel != otp.Email || m.Org != "hanzo" {
		t.Fatalf("to %q over %q as %q; want ada@example.com, email, the token's application's org hanzo", m.To, m.Channel, m.Org)
	}
	if m.Subject != "You're invited to join an organization" || !strings.Contains(m.Body, "join Acme Robotics.") {
		t.Fatalf("subject %q", m.Subject)
	}
	link := "https://hanzo.id/join?client_id=hanzo-app&amp;invite=K7PQ2M9XRT&amp;org=acme"
	if strings.Count(m.Body, "<a ") != 1 || !strings.Contains(m.Body, `<a href="`+link+`">`) {
		t.Fatalf("want exactly one anchor, to %s:\n%s", link, m.Body)
	}
}

// HIGH 1: the sender and the link are the token's. A request cannot name another
// brand's application, and the Host header moves neither.
func TestSend_theTokenDecidesSenderAndLink(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "inv-1", "ada@example.com")

	lux := h.access(t, "acme/owner", "lux-app", "https://lux.id", "access-token")
	if status, body := h.send(t, lux, "hanzo.id", sendPath, `{"application":"admin/globex-console"}`); status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	m := box.messages()[0]
	if m.Org != "lux" || !strings.Contains(m.Body, `href="https://lux.id/join?client_id=lux-app&amp;`) {
		t.Fatalf("sent as %q with body:\n%s\nwant lux's account and a lux.id link", m.Org, m.Body)
	}
}

// HIGH 1 / MEDIUM 1: a tenant's application, an ID token and a plain token with no
// client send nothing.
func TestSend_onlyThePlatformsAccessTokens(t *testing.T) {
	for name, bearer := range map[string]func(h *harness) string{
		"a tenant's application": func(h *harness) string {
			return h.access(t, "acme/owner", "globex-console", "https://hanzo.id", "access-token")
		},
		"an ID token":            func(h *harness) string { return h.access(t, "acme/owner", "hanzo-app", "https://hanzo.id", "id-token") },
		"a token with no client": func(h *harness) string { return h.token(t, "acme/owner") },
	} {
		t.Run(name, func(t *testing.T) {
			h, box := sendRig(t)
			seedPinned(t, h.db, "inv-1", "ada@example.com")
			if status, body := h.send(t, bearer(h), "hanzo.id", sendPath, `{}`); status != 403 {
				t.Fatalf("status=%d body=%s, want 403", status, body)
			}
			if len(box.messages()) != 0 {
				t.Fatal("a refused send mailed")
			}
		})
	}
}

// A name somebody chose is text a mail client cannot act on: no markup, no line,
// nothing URL-shaped for it to link, and never in the subject.
func TestSend_namesCarryNothingToFollow(t *testing.T) {
	h, box := sendRig(t)
	o, _ := store.GetOrganizationByName(context.Background(), h.db, "acme")
	o.DisplayName = "Hanzo Security</b><br><a href=\"https://hanzo-id.example/verify\">Your account is locked</a><!--\r\nBcc: x@evil.example www.hanzo-id.example"
	if err := o.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	m := box.messages()[0]
	if m.Subject != "You're invited to join an organization" {
		t.Fatalf("subject %q carries the name", m.Subject)
	}
	lead := m.Body[:strings.Index(m.Body, "</p>")]
	for _, bad := range []string{"<a", "<br", "<!--", "://", "hanzo-id.example", "www.", "@", "\n"} {
		if strings.Contains(lead, bad) {
			t.Fatalf("the name left %q in the body:\n%s", bad, m.Body)
		}
	}
	if strings.Count(m.Body, "<a ") != 1 {
		t.Fatalf("want one anchor:\n%s", m.Body)
	}
}

// HIGH 2: an invitation reaches one bare address, or nobody.
func TestSend_theRecipientIsOneBareAddress(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "inv-1", `"Hanzo Billing" <victim@example.com>`)
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 400 {
		t.Fatalf("status=%d body=%s, want 400", status, body)
	}
	if len(box.messages()) != 0 {
		t.Fatal("mailed a display-named address")
	}
}

// One mailbox is one person however its address is written: tags and Gmail's
// dots do not buy more mail. One org sends a mailbox at most three a day.
func TestSend_oneMailboxIsPacedAcrossItsAddresses(t *testing.T) {
	h, box := sendRig(t)
	addrs := []string{"ada+1@example.com", "ada+2@example.com", "ADA@example.com", "ada+3@example.com", "ada+4@example.com"}
	for i, a := range addrs {
		seedPinned(t, h.db, fmt.Sprintf("inv-%d", i), a)
	}
	var refused int
	for i := range addrs {
		if status, _ := h.send(t, h.owner(t), "hanzo.id", fmt.Sprintf("/v1/iam/invitations/acme/inv-%d/send", i), `{}`); status == 429 {
			refused++
		}
	}
	if got := len(box.messages()); got != 3 || refused != 2 {
		t.Fatalf("mailed %d, refused %d; want 3 and 2", got, refused)
	}
	if got := box.messages()[0].To; got != "ada+1@example.com" {
		t.Fatalf("delivered to %q, want the address as written", got)
	}
	if schema.Mailbox("a.d.a+x@googlemail.com") != "ada@gmail.com" {
		t.Fatal("a Gmail address is not read as its mailbox")
	}
}

// One org cannot spend a mailbox's day for everyone else: its own limit sits far
// below the limit across orgs.
func TestSend_oneOrgCannotExhaustAMailbox(t *testing.T) {
	h, box := sendRig(t)
	for i := 0; i < 3; i++ {
		if err := store.Append(context.Background(), h.db, &schema.AuditLog{
			Owner: "throwaway", Organization: "throwaway", Action: schema.ActionInviteSend, Object: "ada@example.com",
		}); err != nil {
			t.Fatal(err)
		}
	}
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 200 {
		t.Fatalf("status=%d body=%s, want acme to reach ada after another org's three", status, body)
	}
	if len(box.messages()) != 1 {
		t.Fatal("nothing was sent")
	}
}

// HIGH 2: an org is paced by the hour, counted from the ledger.
func TestSend_oneOrgIsPacedByTheHour(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	for i := 0; i < 50; i++ {
		if err := store.Append(context.Background(), h.db, &schema.AuditLog{
			Owner: "acme", Organization: "acme", Action: schema.ActionInviteSend, Object: "x@example.com",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 429 {
		t.Fatalf("status=%d body=%s, want 429", status, body)
	}
	if len(box.messages()) != 0 {
		t.Fatal("mailed past the org's hour")
	}
}

func TestSend_refusals(t *testing.T) {
	for _, tc := range []struct {
		name, sub, path string
		pin             string
		want            int
	}{
		{"a member who does not administer the org", "acme/bob", sendPath, "ada@example.com", 403},
		{"an admin of another org", "hanzo/boss", sendPath, "ada@example.com", 403},
		{"an invitation pinned to no address", "acme/owner", sendPath, "", 400},
		{"an invitation that does not exist", "acme/owner", "/v1/iam/invitations/acme/inv-9/send", "ada@example.com", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, box := sendRig(t)
			seedPinned(t, h.db, "inv-1", tc.pin)
			bearer := h.access(t, tc.sub, "hanzo-app", "https://hanzo.id", "access-token")
			if status, body := h.send(t, bearer, "hanzo.id", tc.path, `{}`); status != tc.want {
				t.Fatalf("status=%d body=%s, want %d", status, body, tc.want)
			}
			if len(box.messages()) != 0 {
				t.Fatal("a refused send mailed")
			}
		})
	}
}

// A SuperAdmin sends for any org.
func TestSend_superAdmin(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	root := h.access(t, "admin/root", "hanzo-app", "https://hanzo.id", "access-token")
	if status, body := h.send(t, root, "hanzo.id", sendPath, `{}`); status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if len(box.messages()) != 1 {
		t.Fatal("nothing was sent")
	}
}

// Inside a minute the same invitation is not mailed again.
func TestSend_resendTooSoon(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 200 {
		t.Fatalf("first: status=%d body=%s", status, body)
	}
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 429 {
		t.Fatalf("second: status=%d body=%s, want 429", status, body)
	}
	if got := len(box.messages()); got != 1 {
		t.Fatalf("mailed %d times, want once", got)
	}
}

// LOW: a delivery failure answers in general terms — the carrier's own words name
// other tenants' configuration — and does not hold the next send back.
func TestSend_deliveryFailures(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	otp.BindSender(nil)
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 503 {
		t.Fatalf("status=%d body=%s, want 503", status, body)
	}
	box.fail = errors.New(`no email provider configured for org "globex"`)
	otp.BindSender(box)
	status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`)
	if status != 502 || strings.Contains(body, "globex") || strings.Contains(body, "provider") {
		t.Fatalf("status=%d body=%s, want a generic 502", status, body)
	}
	box.fail = nil
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 200 {
		t.Fatalf("after the outage: status=%d body=%s, want 200", status, body)
	}
}

// LOW: putting the send stamp back after a failed delivery touches that field
// alone — a seat spent while the email was in flight stays spent.
func TestSend_releaseKeepsWhatChangedMeanwhile(t *testing.T) {
	h, box := sendRig(t)
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	box.fail = errors.New("smtp down")
	box.during = func() {
		inv, err := orm.Get[schema.Invitation](h.db, "acme/inv-1")
		if err != nil {
			t.Error(err)
			return
		}
		inv.UsedCount, inv.State = 1, "Suspended"
		if err := inv.UpdateCtx(context.Background()); err != nil {
			t.Error(err)
		}
	}
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 502 {
		t.Fatalf("status=%d body=%s, want 502", status, body)
	}
	inv, err := orm.Get[schema.Invitation](h.db, "acme/inv-1")
	if err != nil {
		t.Fatal(err)
	}
	if inv.UsedCount != 1 || inv.State != "Suspended" || inv.SentTime != "" {
		t.Fatalf("after release: used=%d state=%q sent=%q; want 1, Suspended, unstamped", inv.UsedCount, inv.State, inv.SentTime)
	}
}

// LOW: the send and the org's pace are on the audit trail, and no request can
// remove them.
func TestSend_isRecorded(t *testing.T) {
	h, _ := sendRig(t)
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	n, err := store.Recorded(context.Background(), h.db, schema.ActionInviteSend, time.Now().Add(-time.Minute), "Organization", "acme")
	if err != nil || n != 1 {
		t.Fatalf("recorded %d sends (%v), want 1", n, err)
	}
	if !schema.PlatformWritten(schema.ActionInviteSend) {
		t.Fatal("a send record is not protected from the audit CRUD")
	}
}

// POST /v1/iam/invitations with no code answers the created row, carrying the code
// IAM minted: a console reads it from here rather than minting its own.
func TestCreate_answersTheMintedCode(t *testing.T) {
	h, _ := sendRig(t)
	status, body := h.send(t, h.owner(t), "hanzo.id", "/v1/iam/invitations",
		`{"owner":"acme","name":"inv-x","email":"ada@example.com","quota":1,"state":"Active"}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	code, _ := out["code"].(string)
	if len(code) != 20 || out["generated"] != true || out["owner"] != "acme" || out["name"] != "inv-x" || out["email"] != "ada@example.com" {
		t.Fatalf("answer %s", body)
	}
	t.Logf("POST /v1/iam/invitations -> %s", body)
}

// An inviter with no display name is left out of the sentence, never named by a
// mangled address.
func TestSend_anInviterWithoutANameIsLeftOut(t *testing.T) {
	h, box := sendRig(t)
	u, _ := store.GetUserByName(context.Background(), h.db, "acme", "owner")
	u.Email, u.DisplayName = "owner@acme.example", ""
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	seedPinned(t, h.db, "inv-1", "ada@example.com")
	if status, body := h.send(t, h.owner(t), "hanzo.id", sendPath, `{}`); status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	body := box.messages()[0].Body
	if !strings.HasPrefix(body, "<p>You have been invited to join Acme Robotics.</p>") || strings.Contains(body, "owner") {
		t.Fatalf("body %q", body)
	}
}

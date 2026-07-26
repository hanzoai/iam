// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The gate, proven by EXECUTION. Red demonstrated the pre-change endpoint by
// driving 200 anonymous requests through it with nothing refused; these tests
// hold the opposite property the same way, by actually driving it.

// freshLimiter isolates a test from process-wide limiter state.
func freshLimiter(t *testing.T) {
	t.Helper()
	prev := otpGuardLimiter
	otpGuardLimiter = newOTPLimiter()
	t.Cleanup(func() { otpGuardLimiter = prev })
}

// THE LOAD PROOF: a flood against the live handler is refused, and the refusals
// start almost immediately rather than after the money is spent.
func TestOTPGuard_FloodIsRefused(t *testing.T) {
	freshLimiter(t)
	r := newRail(t)
	useRail(t, r)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")

	const attempts = 200
	ok := 0
	for i := 0; i < attempts; i++ {
		_, env := sendCode(t, app, map[string]string{
			"dest": "z@hanzo.ai", "type": "email", "applicationId": "admin/conf",
		})
		if env["status"] == "ok" {
			ok++
		}
	}
	// The destination cooldown means only the FIRST of a tight loop can succeed.
	if ok != 1 {
		t.Fatalf("%d/%d anonymous sends succeeded; want exactly 1 — the rest must be refused", ok, attempts)
	}
	r.mu.Lock()
	sends := len(r.sends)
	r.mu.Unlock()
	if sends != 1 {
		t.Fatalf("the rail was driven %d times by a flood; want 1 — this is the money leak", sends)
	}
}

// Rotating the destination defeats the per-destination limit, so the
// application and global ceilings are what must hold. This is the IRSF shape:
// every request a different attacker-owned number.
func TestOTPGuard_RotatingDestinationsHitTheCeiling(t *testing.T) {
	freshLimiter(t)
	r := newRail(t)
	useRail(t, r)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")

	ok := 0
	for i := 0; i < otpApplicationBurst+50; i++ {
		_, env := sendCode(t, app, map[string]string{
			// A distinct valid +1 number every time — no destination repeats.
			"dest": fmt.Sprintf("+1555%07d", i), "type": "phone", "applicationId": "admin/conf",
		})
		if env["status"] == "ok" {
			ok++
		}
	}
	if ok > otpApplicationBurst {
		t.Fatalf("%d sends allowed; the application ceiling is %d", ok, otpApplicationBurst)
	}
	if ok == 0 {
		t.Fatal("the limiter refused everything — legitimate traffic must pass")
	}
}

// Destination validation, by case. Every one of these reached the transport
// before the gate existed.
func TestOTPGuard_PhoneDestinations(t *testing.T) {
	refused := []string{
		"+900-PREMIUM-RATE",
		"'; DROP TABLE users;--",
		strings.Repeat("9", 4096),
		"+1555010\r\nTo: victim@example.com",
		"15551234567",   // no leading +
		"+0155512345",   // zero country digit
		"+1 555 123 45", // spaces
		"+441234567890", // valid E.164, but outside the dialing allow-list
		"",
	}
	for _, d := range refused {
		if got, err := validPhone(d); err == nil {
			t.Errorf("validPhone(%q) = %q, want refused", d, got)
		}
	}
	for _, d := range []string{"+15551234567", "  +19135550100  "} {
		if _, err := validPhone(d); err != nil {
			t.Errorf("validPhone(%q) must be accepted: %v", d, err)
		}
	}
}

// Email is delivered to the PARSED address, never the raw input — the two differ
// exactly where it matters.
func TestOTPGuard_EmailIsParsedNotRaw(t *testing.T) {
	got, err := validEmail("Alice <victim@example.com>")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got != "victim@example.com" {
		t.Errorf("got %q, want the parsed address victim@example.com — not the display form", got)
	}
	if _, err := validEmail("not-an-email"); err == nil {
		t.Error("a non-address must be refused")
	}
	if got, _ := validEmail("Z@Hanzo.AI"); got != "z@hanzo.ai" {
		t.Errorf("got %q, want a normalized address", got)
	}
}

// The cooldown measures from the LAST attempt, not the window start — the bug
// this test exists to prevent regressing.
func TestOTPGuard_CooldownMeasuresFromLastAttempt(t *testing.T) {
	freshLimiter(t)
	base := time.Now()
	nowFuncSet(t, base)
	if _, err := guardOTP("email", "a@hanzo.ai", "admin/conf"); err != nil {
		t.Fatalf("first send: %v", err)
	}
	// Just inside the cooldown → refused.
	nowFuncSet(t, base.Add(otpDestinationCooldown-time.Second))
	if _, err := guardOTP("email", "a@hanzo.ai", "admin/conf"); err == nil {
		t.Fatal("a send inside the cooldown must be refused")
	}
	// Past the cooldown → allowed, and this attempt restarts the clock.
	nowFuncSet(t, base.Add(otpDestinationCooldown+time.Second))
	if _, err := guardOTP("email", "a@hanzo.ai", "admin/conf"); err != nil {
		t.Fatalf("a send past the cooldown must be allowed: %v", err)
	}
	// One second later must still be refused — proving the window measures from
	// the attempt just made, not from the first attempt in the window.
	nowFuncSet(t, base.Add(otpDestinationCooldown+2*time.Second))
	if _, err := guardOTP("email", "a@hanzo.ai", "admin/conf"); err == nil {
		t.Fatal("the cooldown must restart from the most recent attempt")
	}
}

// Expired records are pruned, so an anonymous caller cannot grow the store
// without bound.
func TestOTPGuard_ExpiredRecordsArePruned(t *testing.T) {
	freshLimiter(t)
	r := newRail(t)
	useRail(t, r)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")
	ctx := context.Background()

	base := time.Now()
	nowFuncSet(t, base)
	if _, env := sendCode(t, app, map[string]string{
		"dest": "old@hanzo.ai", "type": "email", "applicationId": "admin/conf",
	}); env["status"] != "ok" {
		t.Fatalf("seed send failed: %v", env)
	}
	if rec, _ := storeLatest(t, db, "old@hanzo.ai"); rec == nil {
		t.Fatal("the seed record was not persisted")
	}

	// Well past the TTL, a later send prunes the stale row.
	nowFuncSet(t, base.Add(2*verificationCodeTTL))
	if _, env := sendCode(t, app, map[string]string{
		"dest": "new@hanzo.ai", "type": "email", "applicationId": "admin/conf",
	}); env["status"] != "ok" {
		t.Fatalf("second send failed: %v", env)
	}
	if rec, _ := storeLatest(t, db, "old@hanzo.ai"); rec != nil {
		t.Error("an expired verification record must be pruned")
	}
	if rec, _ := storeLatest(t, db, "new@hanzo.ai"); rec == nil {
		t.Error("the live record must survive the prune")
	}
	_ = ctx
}

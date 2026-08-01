// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package risk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// scorer stands up a real HTTP scorer so the client is exercised end to end —
// serialization, headers, status handling and the budget — rather than through a
// fake that could agree with a wrong implementation.
func scorer(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv(URLEnv, srv.URL)
	return New("service-token")
}

// slow answers correctly but too late. It sleeps rather than blocking on the
// request context so the test server can always shut down — a test that can hang
// is a test that will.
func slow(w http.ResponseWriter, _ *http.Request) {
	time.Sleep(4 * Budget)
	_ = json.NewEncoder(w).Encode(Verdict{Action: ActionAllow})
}

func answers(v Verdict) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func TestDecide_PassesAScoredVerdictThrough(t *testing.T) {
	c := scorer(t, answers(Verdict{ID: "d-1", Action: ActionBlock, Score: 0.93, Cause: "velocity"}))
	v := c.Decide(context.Background(), Query{Stage: StageSignup, Org: "acme"})
	if !v.Scored() || v.Action != ActionBlock || v.ID != "d-1" {
		t.Fatalf("verdict was reshaped in transit: %+v", v)
	}
}

// The tenant is a HEADER, never a body field: a tenant in the body is a tenant
// the caller asserted for itself.
func TestDecide_SendsTheTenantAsAHeaderAndNeverInTheBody(t *testing.T) {
	var gotOrg string
	var body map[string]any
	c := scorer(t, func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("X-Org-Id")
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(Verdict{Action: ActionAllow})
	})
	c.Decide(context.Background(), Query{Stage: StageSignup, Org: "acme", Privileged: true})

	if gotOrg != "acme" {
		t.Fatalf("X-Org-Id = %q, want acme", gotOrg)
	}
	for _, forbidden := range []string{"org", "Org", "organization", "privileged", "Privileged"} {
		if _, ok := body[forbidden]; ok {
			t.Fatalf("%q must not be serialized into the body: %v", forbidden, body)
		}
	}
}

func TestDecide_FailsOpenOnTheOrdinaryPath(t *testing.T) {
	ordinary := Query{Stage: StageSignup, Org: "acme"}

	cases := []struct {
		name    string
		build   func(*testing.T) *Client
		refusal string
	}{
		{"unconfigured", func(t *testing.T) *Client {
			t.Setenv(URLEnv, "")
			return New("service-token")
		}, RefusalAbsent},
		{"no credential", func(t *testing.T) *Client {
			t.Setenv(URLEnv, "https://api.example.test")
			return New("")
		}, RefusalAbsent},
		{"scorer 500s", func(t *testing.T) *Client {
			return scorer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
		}, RefusalError},
		{"scorer answers garbage", func(t *testing.T) *Client {
			return scorer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) })
		}, RefusalError},
		{"scorer answers with no action", func(t *testing.T) *Client {
			return scorer(t, answers(Verdict{Score: 0.5}))
		}, RefusalSilent},
		{"scorer answers outside the vocabulary", func(t *testing.T) *Client {
			return scorer(t, answers(Verdict{Action: "quarantine"}))
		}, RefusalUnknown},
		{"scorer answers past the budget", func(t *testing.T) *Client {
			return scorer(t, slow)
		}, RefusalError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.build(t).Decide(context.Background(), ordinary)
			if v.Action != ActionAllow {
				t.Fatalf("an ordinary sign-up must FAIL OPEN: action = %q", v.Action)
			}
			if v.Refusal != tc.refusal {
				t.Fatalf("refusal = %q, want %q", v.Refusal, tc.refusal)
			}
			if v.Scored() {
				t.Fatal("an unscored allow must not report itself as scored")
			}
		})
	}
}

// An ARMED deployment whose scorer is momentarily down must not mint a tenant.
func TestDecide_FailsClosedOnAPrivilegedGrantWhenArmed(t *testing.T) {
	grant := Query{Stage: StageSignup, Org: "acme", Privileged: true}

	cases := []struct {
		name  string
		build func(*testing.T) *Client
	}{
		{"scorer 500s", func(t *testing.T) *Client {
			return scorer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
		}},
		{"scorer unreachable", func(t *testing.T) *Client {
			t.Setenv(URLEnv, "http://127.0.0.1:1") // nothing listens here
			return New("service-token")
		}},
		{"scorer answers with no action", func(t *testing.T) *Client {
			return scorer(t, answers(Verdict{}))
		}},
		{"scorer answers outside the vocabulary", func(t *testing.T) *Client {
			return scorer(t, answers(Verdict{Action: "maybe"}))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.build(t).Decide(context.Background(), grant)
			if v.Action != ActionBlock {
				t.Fatalf("a privileged grant on an ARMED deployment must FAIL CLOSED: action = %q", v.Action)
			}
			if v.Refusal == "" {
				t.Fatal("a fail-closed block must name why it could not be scored")
			}
		})
	}
}

// The one refusal that does NOT fail closed. A deployment that was never pointed
// at a risk plane must still be able to onboard a tenant; refusing there would be
// an outage wearing a defense's clothes, and it is recorded rather than silent.
func TestDecide_AnUnarmedDeploymentStillOnboards(t *testing.T) {
	t.Setenv(URLEnv, "")
	c := New("service-token")
	if c.Configured() {
		t.Fatal("an unset RISK_URL must not read as configured")
	}
	v := c.Decide(context.Background(), Query{Stage: StageSignup, Org: "acme", Privileged: true})
	if v.Action != ActionAllow {
		t.Fatalf("an unarmed deployment must allow tenant creation: action = %q", v.Action)
	}
	if v.Refusal != RefusalAbsent {
		t.Fatalf("refusal = %q, want %q — the darkness must be recorded", v.Refusal, RefusalAbsent)
	}
}

// A scored allow on a privileged grant is honoured: Privileged selects a BRANCH
// of the fail policy, it does not deny on its own.
func TestDecide_PrivilegedIsNotItselfADenial(t *testing.T) {
	c := scorer(t, answers(Verdict{ID: "d-9", Action: ActionAllow}))
	if v := c.Decide(context.Background(), Query{Stage: StageSignup, Privileged: true}); v.Action != ActionAllow {
		t.Fatalf("a scored allow must be honoured, got %q", v.Action)
	}
}

// The budget is the caller's. A scorer that never answers must not hold a
// sign-up open.
func TestDecide_ReturnsInsideTheBudget(t *testing.T) {
	c := scorer(t, slow)
	start := time.Now()
	c.Decide(context.Background(), Query{Stage: StageSignup})
	if elapsed := time.Since(start); elapsed > 10*Budget {
		t.Fatalf("Decide took %s; the budget is %s", elapsed, Budget)
	}
}

// A nil client is a working, safe client: a caller never has to branch on
// whether risk is wired.
func TestDecide_NilClientIsSafe(t *testing.T) {
	var c *Client
	if c.Configured() {
		t.Fatal("a nil client is not configured")
	}
	if v := c.Decide(context.Background(), Query{Stage: StageSignup}); v.Action != ActionAllow {
		t.Fatalf("a nil client must allow an ordinary sign-up, got %q", v.Action)
	}
}

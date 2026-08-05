// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Consent has ONE writer. These tests are the two ways that could stop being
// true: another endpoint reaching the same record, and this endpoint answering a
// question the request never asked.

// The preferences surface shallow-merges whatever top-level keys a client sends,
// unvalidated and unaudited. The consent record lives in that same blob — so
// without this refusal, `POST /v1/iam/preferences {"consent":{...}}` is a second
// writer of the one record that most needs a single one, and it bypasses the
// answer validation and the audit row that make the real one accountable.
func TestPreferencesRefusesTheConsentKey(t *testing.T) {
	for _, patch := range []string{
		`{"consent":{"training":"granted"}}`,
		`{"theme":"dark","consent":{"training":"granted"}}`,
		`{"consent":null}`,
		`{"consent":"granted"}`,
	} {
		t.Run(patch, func(t *testing.T) {
			_, _, err := mergePreferences(`{"consent":{"insights":true,"training":"refused"}}`, []byte(patch))
			if err == nil {
				t.Fatalf("the preferences surface accepted a consent patch: %s", patch)
			}
			if !strings.Contains(err.Error(), PathConsent) {
				t.Fatalf("the refusal must say where to answer instead, got: %v", err)
			}
		})
	}

	// And it still merges everything that IS a preference.
	merged, m, err := mergePreferences(`{"consent":{"training":"granted"},"theme":"light"}`, []byte(`{"theme":"dark"}`))
	if err != nil {
		t.Fatalf("an ordinary preference patch was refused: %v", err)
	}
	if got := string(m["theme"]); got != `"dark"` {
		t.Fatalf("theme = %s, want \"dark\"", got)
	}
	// The stored consent is untouched by a write it is not part of.
	if !schema.ConsentOf(merged).MayTrain() {
		t.Fatalf("a preferences write altered the stored consent: %s", merged)
	}
}

// putConsent takes a raw JSON body so a test can express the difference between
// "absent" and "present and false" — which is the whole property under test.
func putConsent(t *testing.T, app *zip.App, cookie, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest("PUT", PathConsent, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	resp, raw := do(t, app, req)
	return resp.StatusCode, decode(t, raw)
}

func consentOnRow(t *testing.T, db orm.DB) schema.Consent {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	if err != nil || u == nil {
		t.Fatalf("read back alice: %v", err)
	}
	return u.Consent()
}

// A consent screen saves the switch the person just moved. If an absent field
// meant "false", saving one switch would silently revoke the other — the person
// would answer one question and have a second answer changed on their behalf,
// which is exactly what consent may not be.
func TestConsentPutLeavesAnUnaskedQuestionAlone(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := sessionCookieFor(t, app)

	// Establish a full record: insights on, training granted.
	if status, env := putConsent(t, app, cookie, `{"insights":true,"training":"granted"}`); status != 200 || env["status"] != "ok" {
		t.Fatalf("initial save: status=%d env=%v", status, env)
	}
	if got := consentOnRow(t, db); !got.MayTrain() || !got.Insights {
		t.Fatalf("initial save did not land: %+v", got)
	}

	t.Run("training-only save keeps insights", func(t *testing.T) {
		if status, _ := putConsent(t, app, cookie, `{"training":"refused"}`); status != 200 {
			t.Fatalf("status=%d", status)
		}
		got := consentOnRow(t, db)
		if got.Training != schema.Refused {
			t.Fatalf("Training = %q, want refused", got.Training)
		}
		if !got.Insights {
			t.Fatal("a training-only save revoked the insights consent the person never touched")
		}
	})

	t.Run("insights-only save keeps training", func(t *testing.T) {
		if status, _ := putConsent(t, app, cookie, `{"insights":false}`); status != 200 {
			t.Fatalf("status=%d", status)
		}
		got := consentOnRow(t, db)
		if got.Insights {
			t.Fatal("insights=false did not land")
		}
		if got.Training != schema.Refused {
			t.Fatalf("an insights-only save changed the training answer to %q", got.Training)
		}
	})

	t.Run("an explicit false is still an answer", func(t *testing.T) {
		// The tri-state must not turn into "absent and false are the same": a
		// person who deliberately switches insights off must be recorded off.
		if status, _ := putConsent(t, app, cookie, `{"insights":true}`); status != 200 {
			t.Fatalf("status=%d", status)
		}
		if !consentOnRow(t, db).Insights {
			t.Fatal("insights=true did not land")
		}
		if status, _ := putConsent(t, app, cookie, `{"insights":false}`); status != 200 {
			t.Fatalf("status=%d", status)
		}
		if consentOnRow(t, db).Insights {
			t.Fatal("an explicit insights=false was read as absent and ignored")
		}
	})

	t.Run("an empty body changes nothing", func(t *testing.T) {
		before := consentOnRow(t, db)
		if status, _ := putConsent(t, app, cookie, `{}`); status != 200 {
			t.Fatalf("status=%d", status)
		}
		if after := consentOnRow(t, db); after != before {
			t.Fatalf("an empty body rewrote the record: %+v -> %+v", before, after)
		}
	})

	t.Run("an unknown answer is refused and stores nothing", func(t *testing.T) {
		before := consentOnRow(t, db)
		status, env := putConsent(t, app, cookie, `{"training":"yes"}`)
		if status == 200 && env["status"] == "ok" {
			t.Fatal("training=\"yes\" was accepted")
		}
		if after := consentOnRow(t, db); after != before {
			t.Fatalf("a refused request still wrote: %+v -> %+v", before, after)
		}
	})
}

// The audit row is the evidence that the answer was given, so it must carry the
// WHOLE record — an insights withdrawal is as much a consent event as a training
// grant — and it must be attributable without recording an address that only
// identifies our own ingress.
func TestConsentChangeIsAudited(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := sessionCookieFor(t, app)

	rows := func() []*schema.AuditLog {
		t.Helper()
		got, err := orm.TypedQuery[schema.AuditLog](db).Filter("owner", "hanzo").GetAll(context.Background())
		if err != nil {
			t.Fatalf("read audit rows: %v", err)
		}
		return got
	}

	if status, _ := putConsent(t, app, cookie, `{"insights":true,"training":"granted"}`); status != 200 {
		t.Fatalf("status=%d", status)
	}
	after := rows()
	if len(after) != 1 {
		t.Fatalf("a consent grant wrote %d audit rows, want 1", len(after))
	}
	row := after[0]
	if row.Action != schema.ActionConsentTraining {
		t.Fatalf("Action = %q", row.Action)
	}
	if !schema.PlatformWritten(row.Action) {
		t.Fatal("the consent action is not reserved, so the row can be forged or deleted through the audit CRUD")
	}
	if row.User != "hanzo/alice" {
		t.Fatalf("User = %q, want the answering subject", row.User)
	}
	if row.ClientIp != "" {
		t.Fatalf("ClientIp = %q — behind the ingress this identifies nothing and is personal data we then owe an answer for", row.ClientIp)
	}
	var change consentChange
	if err := json.Unmarshal([]byte(row.Object), &change); err != nil {
		t.Fatalf("audited object is not a consent change: %q", row.Object)
	}
	if change.To.Training != schema.Granted || change.From.Training != schema.Unanswered {
		t.Fatalf("the transition was not recorded: %+v", change)
	}

	// An insights-only change is a consent event too.
	if status, _ := putConsent(t, app, cookie, `{"insights":false}`); status != 200 {
		t.Fatalf("status=%d", status)
	}
	if got := rows(); len(got) != 2 {
		t.Fatalf("an insights withdrawal wrote %d rows in total, want 2 — only the training answer is being audited", len(got))
	}

	// Re-saving an unchanged screen is not an event.
	if status, _ := putConsent(t, app, cookie, `{"insights":false}`); status != 200 {
		t.Fatalf("status=%d", status)
	}
	if got := rows(); len(got) != 2 {
		t.Fatalf("a no-op save wrote an audit row (%d rows)", len(got))
	}
}

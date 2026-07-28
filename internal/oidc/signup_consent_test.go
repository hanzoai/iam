// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The signup screen is where the training question gets asked, so the answer is
// recorded WITH the account. These tests pin the two halves of that: an answer the
// screen collected is stored verbatim, and every way of not answering ends up as a
// record that refuses.

// signupConsent runs a signup and returns the stored user's decoded consent.
func signupConsent(t *testing.T, app *zip.App, db orm.DB, org, user string, body map[string]string) schema.Consent {
	t.Helper()
	status, env := signupReq(t, app, body)
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("signup status=%d env=%v, want 200 ok", status, env)
	}
	stored, err := store.GetUserByName(context.Background(), db, org, user)
	if err != nil || stored == nil {
		t.Fatalf("stored user %s/%s: %v", org, user, err)
	}
	return stored.Consent()
}

func consentSignupBody(user, training string) map[string]string {
	b := map[string]string{
		"application":  "conf",
		"organization": "hanzo",
		"username":     user,
		"password":     "correct horse battery staple",
		"email":        user + "@hanzo.ai",
	}
	if training != "" {
		b["training"] = training
	}
	return b
}

func newConsentSignupServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")
	return app, db
}

// A signup that never mentions training must produce an account that is NOT
// trainable on. This is the case that matters most, because it is what every
// client that has not been taught to ask will send.
func TestSignup_SilenceIsRefusal(t *testing.T) {
	app, db := newConsentSignupServer(t)
	got := signupConsent(t, app, db, "hanzo", "quiet", consentSignupBody("quiet", ""))
	if got.MayTrain() {
		t.Fatal("a signup that never asked about training produced a trainable account")
	}
	if got.Training != schema.Unanswered {
		t.Fatalf("Training = %q, want Unanswered", got.Training)
	}
}

// An explicit grant from the screen is recorded, so the answer does not have to be
// asked again. Without this the suite could pass with a signup that hard-codes a
// refusal, which would look safe and be wrong.
func TestSignup_GrantIsRecorded(t *testing.T) {
	app, db := newConsentSignupServer(t)
	got := signupConsent(t, app, db, "hanzo", "willing", consentSignupBody("willing", "granted"))
	if !got.MayTrain() {
		t.Fatal("an explicit grant at signup was not recorded")
	}
	if got.Training != schema.Granted {
		t.Fatalf("Training = %q, want %q", got.Training, schema.Granted)
	}
}

// An explicit refusal is recorded AS a refusal — distinct from silence — so the
// screen knows not to ask again and the answer is provable.
func TestSignup_RefusalIsRecorded(t *testing.T) {
	app, db := newConsentSignupServer(t)
	got := signupConsent(t, app, db, "hanzo", "unwilling", consentSignupBody("unwilling", "refused"))
	if got.MayTrain() {
		t.Fatal("a refusal produced a trainable account")
	}
	if got.Training != schema.Refused {
		t.Fatalf("Training = %q, want %q — a refusal collapsed into silence", got.Training, schema.Refused)
	}
}

// An answer this version does not recognize is refused at the boundary: the signup
// fails and NO account is created. Coercing it would persist a value whose meaning
// a later reader has to guess.
func TestSignup_UnknownAnswerIsRejected(t *testing.T) {
	app, db := newConsentSignupServer(t)
	for _, bad := range []string{"true", "yes", "1", "Granted", "GRANTED", "granted ", "allow"} {
		t.Run(bad, func(t *testing.T) {
			status, env := signupReq(t, app, consentSignupBody("sneaky-"+bad, bad))
			if env["status"] == "ok" {
				t.Fatalf("signup with training=%q succeeded (status=%d env=%v)", bad, status, env)
			}
			stored, err := store.GetUserByName(context.Background(), db, "hanzo", "sneaky-"+bad)
			if err == nil && stored != nil {
				t.Fatalf("signup with training=%q was refused but still created an account", bad)
			}
		})
	}
}

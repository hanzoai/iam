// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// When somebody last signed in is recorded by SIGNING IN, not by a unit calling
// the writer. A periodic access review reads this column to find the accounts
// nobody uses any more, so it has to be true of the real endpoint.
func TestLogin_recordsWhenTheySignedIn(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db) // hanzo/alice, password "pw"
	ctx := context.Background()

	before, err := store.GetUserByName(ctx, db, "hanzo", "alice")
	if err != nil || before == nil {
		t.Fatalf("seed: %v", err)
	}
	if before.LastSigninTime != "" {
		t.Fatalf("an account that has never signed in carries %q", before.LastSigninTime)
	}

	form := url.Values{
		"organization": {"hanzo"},
		"application":  {"conf"},
		"username":     {"alice"},
		"password":     {"pw"},
		"type":         {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, body)
	}

	after, err := store.GetUserByName(ctx, db, "hanzo", "alice")
	if err != nil || after == nil {
		t.Fatalf("read back: %v", err)
	}
	if after.LastSigninTime == "" {
		t.Fatal("a real sign-in recorded nothing — the column stays empty for accounts in daily use")
	}
}

// A refused attempt is not a sign-in. Recording one would make the column read
// "in use" for an account nobody can actually get into.
func TestLogin_aRefusedAttemptRecordsNothing(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	ctx := context.Background()

	form := url.Values{
		"organization": {"hanzo"},
		"application":  {"conf"},
		"username":     {"alice"},
		"password":     {"wrong"},
		"type":         {"login"},
	}
	do(t, app, formReq("POST", PathLogin, form))

	after, err := store.GetUserByName(ctx, db, "hanzo", "alice")
	if err != nil || after == nil {
		t.Fatalf("read back: %v", err)
	}
	if after.LastSigninTime != "" {
		t.Fatalf("a wrong password recorded a sign-in at %q", after.LastSigninTime)
	}
}

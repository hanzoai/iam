// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package e2e_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/provision"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/store"
)

// The operator's own journey: a provision document converged against the real
// router, by the real reconciler, twice — which is how it is actually run (a
// reconcile loop, not a one-shot). What the document declares must land, a re-run
// must change nothing, and an account the document did NOT create must be refused
// rather than absorbed.

// serviceToken is the operator's credential for this surface — the one the
// reconciler presents and the one the routes validate against.
const serviceToken = "svc-token-secret-value"

const provisionDoc = `
orgs:
  - name: hanzo
    displayName: Hanzo
    accounts:
      - name: zed
        type: owner
        email: zed@hanzo.ai
        displayName: Zed
        passwordRef: kms://hanzo/iam/owner
  - name: admin
    displayName: Hanzo Platform
    accounts:
      - name: provisioner
        type: service
        displayName: Platform Provisioner
        passwordRef: kms://hanzo/iam/service/provisioner
`

// router lets the reconciler's http.Client reach the registered routes in
// process — the reconciler speaks HTTP and this is that, without a listener.
type router struct{ e *env }

func (r router) RoundTrip(req *http.Request) (*http.Response, error) {
	return testhttp.Do(r.e.app, req)
}

func (e *env) converge(t *testing.T, dir string) *provision.Reconciler {
	t.Helper()
	return &provision.Reconciler{
		BaseURL:     "http://hanzo.id",
		Token:       serviceToken,
		HTTP:        &http.Client{Transport: router{e}},
		Credentials: provision.DirCredentials(dir),
	}
}

func material(t *testing.T, dir, rel, body string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func accounts(t *testing.T, src string) []provision.OrgAccount {
	t.Helper()
	doc, err := provision.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return provision.Accounts(doc)
}

// TestJourney_Provision_ConvergesAndStaysConverged — the declared accounts land
// with the authority their type implies, and the second run is a no-op down to the
// stored digest. A reconcile that re-hashed would rotate, every loop, the
// credential the running services are holding.
func TestJourney_Provision_ConvergesAndStaysConverged(t *testing.T) {
	t.Setenv("IAM_SERVICE_TOKEN", serviceToken)
	e := boot(t)
	dir := t.TempDir()
	material(t, dir, "hanzo/iam/owner", "correct-horse-battery-staple\n")
	material(t, dir, "hanzo/iam/service/provisioner", "a-machine-credential")

	declared := accounts(t, provisionDoc)
	for _, res := range e.converge(t, dir).ApplyAccounts(context.Background(), declared) {
		if res.Err != nil || res.Action != "created" {
			t.Fatalf("%s/%s: action=%q err=%v", res.Account.Org, res.Account.Account.Name, res.Action, res.Err)
		}
	}

	owner, err := store.GetUserByName(context.Background(), e.db, "hanzo", "zed")
	if err != nil || owner == nil {
		t.Fatalf("owner not created: %v", err)
	}
	if !owner.IsAdmin {
		t.Error("the declared owner did not get the org-admin bit its type implies")
	}
	svc, err := store.GetUserByName(context.Background(), e.db, "admin", "provisioner")
	if err != nil || svc == nil {
		t.Fatalf("service account not created: %v", err)
	}
	if svc.IsAdmin {
		t.Error("the declared machine got an org-admin bit it has no use for")
	}

	for _, res := range e.converge(t, dir).ApplyAccounts(context.Background(), declared) {
		if res.Err != nil || res.Action != "updated" {
			t.Fatalf("re-run %s/%s: action=%q err=%v", res.Account.Org, res.Account.Account.Name, res.Action, res.Err)
		}
	}
	again, _ := store.GetUserByName(context.Background(), e.db, "hanzo", "zed")
	if again.PasswordHash != owner.PasswordHash {
		t.Errorf("a re-run rotated the credential:\n  %s\n  %s", owner.PasswordHash, again.PasswordHash)
	}
	if again.UpdatedTime != owner.UpdatedTime {
		t.Errorf("a re-run rewrote the row: updatedTime %s -> %s", owner.UpdatedTime, again.UpdatedTime)
	}
}

// TestJourney_Provision_RefusesAnAccountItDidNotCreate — alice already holds her
// name in the hanzo org. A document that declares that name describes a row this
// declaration never created, so the converge must answer it by name and leave both
// her authority and her credential exactly as they were.
func TestJourney_Provision_RefusesAnAccountItDidNotCreate(t *testing.T) {
	t.Setenv("IAM_SERVICE_TOKEN", serviceToken)
	e := boot(t)
	dir := t.TempDir()
	material(t, dir, "hanzo/iam/owner", "correct-horse-battery-staple")

	before, err := store.GetUserByName(context.Background(), e.db, "hanzo", "alice")
	if err != nil || before == nil {
		t.Fatalf("alice: %v", err)
	}

	claim := strings.Replace(provisionDoc, "name: zed", "name: alice", 1)
	res := e.converge(t, dir).ApplyAccounts(context.Background(), accounts(t, claim))
	if res[0].Err == nil {
		t.Fatalf("hanzo/alice was converged by a declaration that never created her: %+v", res[0])
	}
	if !strings.Contains(res[0].Err.Error(), "hanzo/alice") {
		t.Errorf("the refusal does not name the account: %v", res[0].Err)
	}

	after, _ := store.GetUserByName(context.Background(), e.db, "hanzo", "alice")
	if after.IsAdmin != before.IsAdmin {
		t.Error("isAdmin moved on an account the declaration does not own")
	}
	if after.PasswordHash != before.PasswordHash {
		t.Error("the credential moved on an account the declaration does not own")
	}
}

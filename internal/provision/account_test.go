// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package provision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// doc is the smallest document that declares both account types: a brand org
// with its human superuser, and the RESERVED admin org carrying the platform
// service account. That pairing is the whole point — platform sudo is membership
// of `admin`, so the service account has to be declared under `admin` and
// nowhere else.
const accountDoc = `
orgs:
  - name: hanzo
    displayName: Hanzo
    accounts:
      - name: z
        type: owner
        email: z@hanzo.ai
        displayName: Z
        passwordRef: kms://hanzo/iam/owner
    apps:
      - app: cloud
        type: confidential
        hosts: [cloud.hanzo.ai]
  - name: admin
    displayName: Hanzo Platform
    accounts:
      - name: provisioner
        type: service
        displayName: Platform Provisioner
        passwordRef: kms://hanzo/iam/service/provisioner
`

func parse(t *testing.T, src string) *Doc {
	t.Helper()
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

// TestAccountsDerive — both account types come off one document in document
// order, and each carries the isAdmin bit its TYPE implies.
func TestAccountsDerive(t *testing.T) {
	accts := Accounts(parse(t, accountDoc))
	if len(accts) != 2 {
		t.Fatalf("want 2 accounts, got %d: %+v", len(accts), accts)
	}
	if accts[0].Org != "hanzo" || accts[0].Account.Name != "z" || accts[0].Account.Type != AccountOwner {
		t.Errorf("first account = %+v, want hanzo/z owner", accts[0])
	}
	if accts[1].Org != "admin" || accts[1].Account.Name != "provisioner" || accts[1].Account.Type != AccountService {
		t.Errorf("second account = %+v, want admin/provisioner service", accts[1])
	}

	// THE least-privilege property, pinned: the service account is provisioned
	// with isAdmin FALSE. Its platform authority comes from membership of the
	// reserved admin org (authz.Claims.PlatformSudo), which never reads this bit,
	// so clearing it removes the org-admin self-service grant and removes nothing
	// else. A change that flips this is a widening and must fail here.
	r := &Reconciler{}
	owner, err := r.user(accts[0])
	if err != nil {
		t.Fatal(err)
	}
	svc, err := r.user(accts[1])
	if err != nil {
		t.Fatal(err)
	}
	if !owner.IsAdmin {
		t.Error("owner account: isAdmin = false, want true")
	}
	if svc.IsAdmin {
		t.Error("service account: isAdmin = true, want false — a machine gets no org-admin bit")
	}
	if svc.Email != "" {
		t.Errorf("service account carries email %q", svc.Email)
	}
	if svc.Owner != "admin" {
		t.Errorf("service account owner = %q, want admin", svc.Owner)
	}
}

// TestAccountsPlanCarriesNoCredential — the derived plan is what --dry-run
// prints and what a reviewer reads, so it must not be able to contain a secret.
// Accounts() takes no resolver and the Account it returns has no field to hold
// one; this pins that by serialising the whole plan and looking for the ref's
// VALUE.
func TestAccountsPlanCarriesNoCredential(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "hanzo/iam/owner", "correct-horse-battery-staple")

	plan, err := json.Marshal(Accounts(parse(t, accountDoc)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plan), "correct-horse") {
		t.Fatalf("the plan carries a credential: %s", plan)
	}
	// The ref itself is fine — it is a location, not a secret.
	if !strings.Contains(string(plan), "kms://hanzo/iam/owner") {
		t.Errorf("the plan lost the passwordRef: %s", plan)
	}
}

func write(t *testing.T, dir, rel, body string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestApplyAccounts — the wire. What the reconciler POSTs, where, and with what
// authorization, plus the two credential outcomes that differ in kind:
// delivered (set it) and absent (preserve it).
func TestApplyAccounts(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "hanzo/iam/owner", "s3cret-owner\n") // trailing newline: mounted material has one
	// admin/provisioner's credential is deliberately NOT written — this run does
	// not carry it, and that must PRESERVE rather than clear.

	type got struct {
		path, auth string
		body       User
	}
	var seen []got
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u User
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			t.Errorf("decode: %v", err)
		}
		seen = append(seen, got{r.URL.Path, r.Header.Get("Authorization"), u})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","action":"created"}`))
	}))
	defer srv.Close()

	r := &Reconciler{BaseURL: srv.URL, Token: "svc-token", Credentials: DirCredentials(dir)}
	res := r.ApplyAccounts(context.Background(), Accounts(parse(t, accountDoc)))

	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	for _, x := range res {
		if x.Err != nil {
			t.Fatalf("%s/%s: %v", x.Account.Org, x.Account.Account.Name, x.Err)
		}
		if x.Action != "created" {
			t.Errorf("%s: action = %q, want created", x.Account.Account.Name, x.Action)
		}
	}
	if !res[0].Credential {
		t.Error("owner: Credential = false, but its material was delivered")
	}
	if res[1].Credential {
		t.Error("service: Credential = true, but no material was delivered — it must report preserve")
	}

	if len(seen) != 2 {
		t.Fatalf("want 2 requests, got %d", len(seen))
	}
	// The report's authority bit is the one that was SENT, not a second derivation
	// beside it — a run report that can disagree with the wire reviews nothing.
	for i, x := range res {
		if x.Admin != seen[i].body.IsAdmin {
			t.Errorf("%s: report says isAdmin=%t, the wire carried %t",
				x.Account.Account.Name, x.Admin, seen[i].body.IsAdmin)
		}
	}
	for _, s := range seen {
		if s.path != "/v1/iam/admin/users/upsert" {
			t.Errorf("path = %q, want /v1/iam/admin/users/upsert", s.path)
		}
		if s.auth != "Bearer svc-token" {
			t.Errorf("authorization = %q", s.auth)
		}
	}
	// Delivered: sent, and the mount's trailing newline is NOT part of the
	// password (hashing it would store a credential nobody can present).
	if seen[0].body.Password != "s3cret-owner" {
		t.Errorf("owner password = %q, want the trimmed material", seen[0].body.Password)
	}
	// Absent: the field is OMITTED, which the endpoint reads as "keep what this
	// account has". An empty string would be indistinguishable on the wire, which
	// is why User.Password is omitempty.
	if seen[1].body.Password != "" {
		t.Error("service: a password was sent though none was resolved")
	}
	raw, _ := json.Marshal(seen[1].body)
	if strings.Contains(string(raw), "password") {
		t.Errorf("service body carries a password key: %s", raw)
	}
}

// TestApplyAccountsDryRunWritesNothing — --dry-run must reach no server.
func TestApplyAccountsDryRunWritesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("dry run made a request")
	}))
	defer srv.Close()

	r := &Reconciler{BaseURL: srv.URL, Token: "t", DryRun: true}
	for _, x := range r.ApplyAccounts(context.Background(), Accounts(parse(t, accountDoc))) {
		if x.Action != "would-upsert" || x.Err != nil {
			t.Errorf("%+v", x)
		}
	}
}

// TestApplyAccountsCredentialFailures — the two ways resolution must FAIL rather
// than converge something wrong.
func TestApplyAccountsCredentialFailures(t *testing.T) {
	t.Run("empty material is refused", func(t *testing.T) {
		// An empty file is not "no credential": hashing "" stores a real digest
		// that an empty password verifies against. users.VerifyPassword's
		// empty-DIGEST guard does not cover it, so it is refused here.
		dir := t.TempDir()
		write(t, dir, "hanzo/iam/owner", "\n")
		r := &Reconciler{BaseURL: "http://127.0.0.1:1", Credentials: DirCredentials(dir)}
		res := r.ApplyAccounts(context.Background(), Accounts(parse(t, accountDoc))[:1])
		if res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "is empty") {
			t.Fatalf("want an empty-credential error, got %v", res[0].Err)
		}
	})

	t.Run("a resolver error never leaks the value", func(t *testing.T) {
		r := &Reconciler{BaseURL: "http://127.0.0.1:1", Credentials: func(string) (string, error) {
			return "the-secret", os.ErrPermission
		}}
		res := r.ApplyAccounts(context.Background(), Accounts(parse(t, accountDoc))[:1])
		if res[0].Err == nil {
			t.Fatal("want an error")
		}
		if strings.Contains(res[0].Err.Error(), "the-secret") {
			t.Fatalf("the error leaks the credential: %v", res[0].Err)
		}
	})
}

// TestDirCredentialsContainment — a credential locator must never become an
// arbitrary file read. Parse rejects a traversing ref, and the resolver refuses
// one anyway; both are asserted because either alone is one refactor from gone.
func TestDirCredentialsContainment(t *testing.T) {
	dir := t.TempDir()
	if _, err := DirCredentials(dir)("../../etc/passwd"); err == nil {
		t.Fatal("DirCredentials followed a traversing path")
	}
	// Absence is os.ErrNotExist — the PRESERVE signal, not a failure.
	if _, err := DirCredentials(dir)("hanzo/iam/owner"); !os.IsNotExist(err) {
		t.Fatalf("missing material: err = %v, want os.ErrNotExist", err)
	}
}

// TestAccountValidation — every way a document is refused before it can touch a
// live tenant. Each case is a distinct defect, not a variation on one.
func TestAccountValidation(t *testing.T) {
	for _, tc := range []struct{ name, accounts, want string }{
		{
			"a service account may not carry an email",
			"      - {name: bot, type: service, email: bot@hanzo.ai, passwordRef: 'kms://a/b'}",
			"must not declare an email",
		},
		{
			"an owner must carry one",
			"      - {name: z, type: owner, passwordRef: 'kms://a/b'}",
			"is not an email address",
		},
		{
			"an unknown type is refused",
			"      - {name: z, type: robot, passwordRef: 'kms://a/b'}",
			"unknown type",
		},
		{
			"a password literal is refused",
			"      - {name: bot, type: service, passwordRef: hunter2}",
			"must be a kms:// locator",
		},
		{
			"a traversing ref is refused",
			"      - {name: bot, type: service, passwordRef: 'kms://../../etc/passwd'}",
			"not a clean relative KMS path",
		},
		{
			// path.Clean keeps a leading "..", and a bare one carries no separator
			// for a "../" test to match — so this is the climb both checks miss.
			"a bare climb is refused",
			"      - {name: bot, type: service, passwordRef: 'kms://..'}",
			"not a clean relative KMS path",
		},
		{
			// A ref that names the credential directory rather than a file in it.
			"the directory itself is refused",
			"      - {name: bot, type: service, passwordRef: 'kms://.'}",
			"not a clean relative KMS path",
		},
		{
			"an absolute ref is refused",
			"      - {name: bot, type: service, passwordRef: 'kms:///etc/passwd'}",
			"not a clean relative KMS path",
		},
		{
			"a missing ref is refused",
			"      - {name: bot, type: service}",
			"passwordRef is required",
		},
		{
			"a name the store would rewrite is refused",
			"      - {name: 'Bot Account', type: service, passwordRef: 'kms://a/b'}",
			"account \"Bot Account\"",
		},
		{
			"one org, one owner",
			"      - {name: a, type: owner, email: a@x.io, passwordRef: 'kms://a/b'}\n" +
				"      - {name: b, type: owner, email: b@x.io, passwordRef: 'kms://a/c'}",
			"at most one",
		},
		{
			"a duplicated account name is refused",
			"      - {name: bot, type: service, passwordRef: 'kms://a/b'}\n" +
				"      - {name: bot, type: service, passwordRef: 'kms://a/c'}",
			"twice",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte("orgs:\n  - name: hanzo\n    accounts:\n" + tc.accounts + "\n"))
			if err == nil {
				t.Fatal("document parsed; want a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestAccountsOptional — an org that manages its accounts elsewhere keeps
// parsing, and derives none. Adding this vocabulary must not require every
// document to use it.
func TestAccountsOptional(t *testing.T) {
	d := parse(t, "orgs:\n  - name: hanzo\n    apps:\n      - {app: cloud, type: service}\n")
	if got := Accounts(d); len(got) != 0 {
		t.Fatalf("want no accounts, got %+v", got)
	}
	if cs, err := Derive(d); err != nil || len(cs) != 1 {
		t.Fatalf("clients = %+v, err = %v", cs, err)
	}
}

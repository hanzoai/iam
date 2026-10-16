package provision

import (
	"os"
	"strings"
	"testing"
)

// TestShippedDocument derives a real org document from disk, so a change to a
// shipped provision.yaml is caught here instead of in production. Each org
// repo points this at its own file in CI:
//
//	IAM_PROVISION_DOC=infra/k8s/iam/provision.yaml go test ./internal/provision/
func TestShippedDocument(t *testing.T) {
	path := os.Getenv("IAM_PROVISION_DOC")
	if path == "" {
		t.Skip("set IAM_PROVISION_DOC to check a shipped document")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(raw)
	if err != nil {
		t.Fatalf("shipped document does not parse: %v", err)
	}
	cs, err := Derive(d)
	if err != nil {
		t.Fatalf("shipped document does not derive: %v", err)
	}
	for _, c := range cs {
		t.Logf("%-16s %s", c.Name, strings.Join(c.RedirectUris, " "))
	}
	if len(cs) == 0 {
		t.Fatal("shipped document derived no clients")
	}

	// Accounts are the other half of the document and get the same gate, or a
	// change to them is caught in production instead of here. The plan is logged
	// rather than asserted against a fixed list — the document owns WHICH
	// accounts exist; this owns that they derive and that each one's authority is
	// what its type says.
	r := &Reconciler{}
	for _, a := range Accounts(d) {
		u, err := r.user(a)
		if err != nil {
			t.Fatalf("account %s/%s does not derive: %v", a.Org, a.Account.Name, err)
		}
		t.Logf("%-16s %-8s isAdmin=%v email=%q", u.Owner+"/"+u.Name, a.Account.Type, u.IsAdmin, u.Email)
		// A platform-sudo account is one declared under the reserved admin org, and
		// no shipped document may ship one carrying an interactive `owner` grant:
		// automation is `service`, humans are `owner`, and a human superuser in the
		// reserved org would be a shared login rather than a named one.
		if u.Owner == "admin" && a.Account.Type != AccountService {
			t.Errorf("account %s/%s is in the reserved admin org with type %q — platform automation is %q",
				u.Owner, u.Name, a.Account.Type, AccountService)
		}
	}
}

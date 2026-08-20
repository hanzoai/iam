// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package provision

import (
	"strings"
	"testing"
)

// TestOrgNameIsTheNameItIsStoredUnder — the document, the plan a reviewer reads
// and the row that lands must be ONE string. The server trims what arrives, so a
// padded name in the document is stored under the trimmed one: the reviewer reads
// a plan naming one org and a tenant is written under another, and no grep for the
// stored name finds the line that produced it. Most of the way that matters is
// `admin`, the reserved org, which a document that never spells it would reach.
func TestOrgNameIsTheNameItIsStoredUnder(t *testing.T) {
	for _, name := range []string{" admin ", "hanzo\t", "\nzoo"} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte("orgs:\n  - name: \"" + name + "\"\n    apps:\n      - {app: cloud, type: service}\n"))
			if err == nil {
				t.Fatalf("org %q parsed; want a refusal naming the spelling it would be stored under", name)
			}
			if !strings.Contains(err.Error(), "stored under") {
				t.Fatalf("error %q does not say what the name would be stored as", err)
			}
		})
	}
}

// TestOrgNameReachesEveryDerivation — one canonical name, everywhere it is read:
// the client's organization and id, and the account's owner.
func TestOrgNameReachesEveryDerivation(t *testing.T) {
	d := parse(t, accountDoc)
	cs, err := Derive(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if strings.TrimSpace(c.Organization) != c.Organization || !strings.HasPrefix(c.Name, c.Organization+"-") {
			t.Errorf("client %+v does not carry its org's canonical name", c)
		}
	}
	for _, a := range Accounts(d) {
		if strings.TrimSpace(a.Org) != a.Org {
			t.Errorf("account %+v does not carry its org's canonical name", a)
		}
	}
}

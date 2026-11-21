// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

func putTenantCert(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm, c.Scope = owner, name, "RS256", schema.CertTenant
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed tenant cert %s/%s: %v", owner, name, err)
	}
}

// The platform resolution never returns a tenant-scoped row, even under a reserved
// owner; the tenant resolution returns only the org's own, only when no platform cert
// answers to the name, and only for an org that may hold an issuer.
func TestTenantCertResolution(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	putCert(t, db, "admin", "cert-hanzo", "")
	putTenantCert(t, db, "admin", "shadow")
	putTenantCert(t, db, "acme", "acme-key")
	putTenantCert(t, db, "acme", "cert-hanzo")
	putTenantCert(t, db, "hanzo", "hanzo-key")
	putCert(t, db, "acme", "plain", "")

	if c, err := GetSigningCert(ctx, db, "shadow"); err != nil || c != nil {
		t.Fatalf("GetSigningCert returned a tenant-scoped row: %v %v", c, err)
	}
	if c, err := GetSigningCert(ctx, db, "cert-hanzo"); err != nil || c == nil || c.Owner != "admin" {
		t.Fatalf("the platform cert cert-hanzo: %v %v", c, err)
	}
	for _, tc := range []struct {
		org, name string
		want      bool
	}{
		{"acme", "acme-key", true},
		{"acme", "cert-hanzo", false}, // a platform cert holds the name
		{"acme", "plain", false},      // not tenant-scoped
		{"acme", "missing", false},
		{"beta", "acme-key", false},   // another org's
		{"hanzo", "hanzo-key", false}, // a platform org holds no tenant cert
		{"admin", "shadow", false},
		{"acme", "", false},
	} {
		c, err := GetTenantCert(ctx, db, tc.org, tc.name)
		if err != nil || (c != nil) != tc.want {
			t.Errorf("GetTenantCert(%q, %q) = %v, %v; want found=%v", tc.org, tc.name, c, err, tc.want)
		}
	}
	list, err := ListTenantCerts(ctx, db, "acme")
	if err != nil || len(list) != 1 || list[0].Name != "acme-key" {
		t.Fatalf("ListTenantCerts(acme) = %v %v", list, err)
	}
	if l, _ := ListTenantCerts(ctx, db, "hanzo"); len(l) != 0 {
		t.Fatalf("a platform org lists tenant certs: %v", l)
	}
	for name, want := range map[string]bool{"cert-hanzo": true, "CERT-HANZO": true, "shadow": true, "acme-key": false} {
		if got, err := PlatformKidTaken(ctx, db, name); err != nil || got != want {
			t.Errorf("PlatformKidTaken(%q) = %v %v, want %v", name, got, err, want)
		}
	}
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keyring

import (
	"context"
	"errors"
	"sync"
	"testing"
)

var any = func(string) bool { return true }

type fake struct {
	mu    sync.Mutex
	m     map[[2]string]string
	reads int
}

func (f *fake) Put(_ context.Context, o, n, p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[[2]string{o, n}]; ok {
		return ErrExists
	}
	f.m[[2]string{o, n}] = p
	return nil
}
func (f *fake) Get(_ context.Context, o, n string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if p, ok := f.m[[2]string{o, n}]; ok {
		return p, nil
	}
	return "", ErrNoKey
}
func (f *fake) Delete(_ context.Context, o, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, [2]string{o, n})
	return nil
}

// With no Vault nothing is created or read; with one, a key is addressed by org and
// name, never overwritten, read once while fresh, and forgotten on delete. A platform
// ring key of the same name is never what a tenant read returns.
func TestVault(t *testing.T) {
	ctx := context.Background()
	UseVault(nil)
	if err := PutTenant(ctx, "acme", "k", "PEM"); !errors.Is(err, ErrNoVault) {
		t.Fatalf("Put with no vault: %v", err)
	}
	if _, err := TenantKey(ctx, "acme", "k", any); !errors.Is(err, ErrNoVault) {
		t.Fatalf("Get with no vault: %v", err)
	}

	f := &fake{m: map[[2]string]string{}}
	UseVault(f)
	t.Cleanup(func() { UseVault(nil); Forget("cert-hanzo") })
	Set("cert-hanzo", "PLATFORM")
	if err := PutTenant(ctx, "acme", "cert-hanzo", "TENANT"); err != nil {
		t.Fatal(err)
	}
	if err := PutTenant(ctx, "acme", "cert-hanzo", "OTHER"); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	if err := PutTenant(ctx, "acme", "../x", "PEM"); err == nil {
		t.Fatal("a name that cannot be a kid was stored")
	}
	for i := 0; i < 3; i++ {
		if k, err := TenantKey(ctx, "acme", "cert-hanzo", any); err != nil || k != "TENANT" {
			t.Fatalf("read %d: %q %v", i, k, err)
		}
	}
	if f.reads != 1 {
		t.Fatalf("vault read %d times, want 1 while the key is fresh", f.reads)
	}
	if _, err := TenantKey(ctx, "beta", "cert-hanzo", any); !errors.Is(err, ErrNoKey) {
		t.Fatalf("another org's read: %v", err)
	}
	if err := DropTenant(ctx, "acme", "cert-hanzo"); err != nil {
		t.Fatal(err)
	}
	if _, err := TenantKey(ctx, "acme", "cert-hanzo", any); !errors.Is(err, ErrNoKey) {
		t.Fatalf("after delete: %v", err)
	}
	// The platform ring is untouched by any of it.
	if got := lookup("cert-hanzo"); got != "PLATFORM" {
		t.Fatalf("platform ring = %q", got)
	}
}

// A cached key is used only for the cert it matches: a cert deleted and created again under
// the same name, with the old key still cached here, is signed with the new key, and a
// vault key that matches nothing is no key.
func TestVaultCacheIsBoundToTheCert(t *testing.T) {
	ctx := context.Background()
	f := &fake{m: map[[2]string]string{}}
	UseVault(f)
	t.Cleanup(func() { UseVault(nil) })
	_ = f.Put(ctx, "acme", "k", "OLD")
	is := func(want string) func(string) bool { return func(p string) bool { return p == want } }
	if k, err := TenantKey(ctx, "acme", "k", is("OLD")); err != nil || k != "OLD" {
		t.Fatalf("first read: %q %v", k, err)
	}
	// Another replica deletes the key and the cert is created again under the same name.
	_ = f.Delete(ctx, "acme", "k")
	_ = f.Put(ctx, "acme", "k", "NEW")
	if k, err := TenantKey(ctx, "acme", "k", is("NEW")); err != nil || k != "NEW" {
		t.Fatalf("after recreate: %q %v; the deleted key was reused", k, err)
	}
	if _, err := TenantKey(ctx, "acme", "k", is("OTHER")); !errors.Is(err, ErrNoKey) {
		t.Fatalf("a vault key matching nothing: %v", err)
	}
}

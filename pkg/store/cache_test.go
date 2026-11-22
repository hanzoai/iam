// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

type memKV struct {
	mu   sync.Mutex
	data map[string][]byte
	gets atomic.Int64
	sets atomic.Int64
	dels atomic.Int64
}

func newMemKV() *memKV {
	return &memKV{data: make(map[string][]byte)}
}

func (m *memKV) Get(_ context.Context, key string) ([]byte, bool) {
	m.gets.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.data[key]
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, true
}

func (m *memKV) Set(_ context.Context, key string, val []byte, _ time.Duration) {
	m.sets.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(val))
	copy(cp, val)
	m.data[key] = cp
}

func (m *memKV) Del(_ context.Context, keys ...string) {
	m.dels.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.data, k)
	}
}

func TestHotCache_ApplicationAndProviderL1L2AndInvalidation(t *testing.T) {
	db, err := Open("sqlite", ":memory:", "")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	l2 := newMemKV()
	EnableCache(time.Minute, l2)
	t.Cleanup(func() {
		DisableCache()
		UseKV(nil)
	})

	ctx := context.Background()
	prov := orm.New[schema.Provider](db)
	prov.Owner = "admin"
	prov.Name = "provider-google"
	prov.Type = "Google"
	prov.ClientId = "google-client-1"
	prov.SetId("admin/provider-google")
	if err := prov.CreateCtx(ctx); err != nil {
		t.Fatalf("create provider: %v", err)
	}

	app := orm.New[schema.Application](db)
	app.Owner = "admin"
	app.Name = "hanzo-app"
	app.ClientId = "hanzo-app"
	app.Organization = "hanzo"
	app.RedirectUris = []string{"https://hanzo.app/auth/callback"}
	app.Providers = []*schema.ProviderItem{
		{Name: "provider-google", CanSignIn: true},
	}
	app.SetId("admin/hanzo-app")
	if err := app.CreateCtx(ctx); err != nil {
		t.Fatalf("create app: %v", err)
	}

	// First read misses L1+L2, populates both.
	got1, err := GetApplicationByClientId(ctx, db, "hanzo-app")
	if err != nil || got1 == nil || got1.ClientId != "hanzo-app" {
		t.Fatalf("first GetApplicationByClientId = (%v, %v)", got1, err)
	}
	if l2.sets.Load() != 1 {
		t.Fatalf("expected 1 L2 set after first app read, got %d", l2.sets.Load())
	}

	// Mutating the returned app's Providers slice must NOT pollute L1.
	got1.Providers[0].Provider = prov

	// Second read hits L1 (no additional L2 get).
	l2GetsBefore := l2.gets.Load()
	got2, err := GetApplicationByClientId(ctx, db, "hanzo-app")
	if err != nil || got2 == nil {
		t.Fatalf("second GetApplicationByClientId = (%v, %v)", got2, err)
	}
	if l2.gets.Load() != l2GetsBefore {
		t.Fatalf("expected L1 hit without L2 get, L2 gets increased from %d to %d", l2GetsBefore, l2.gets.Load())
	}
	if got2.Providers[0].Provider != nil {
		t.Fatalf("cached app leaked mutated transient Provider pointer")
	}

	// Clear L1 only -> next read must hit L2 KV without hitting DB.
	activeCache.Load().mu.Lock()
	activeCache.Load().l1 = make(map[string]cacheEntry)
	activeCache.Load().mu.Unlock()
	got3, err := GetApplicationByClientId(ctx, db, "hanzo-app")
	if err != nil || got3 == nil || got3.ClientId != "hanzo-app" {
		t.Fatalf("L2 GetApplicationByClientId = (%v, %v)", got3, err)
	}
	if l2.gets.Load() != l2GetsBefore+1 {
		t.Fatalf("expected L2 hit after L1 clear, got %d L2 gets", l2.gets.Load())
	}

	// FindLinkedProvider resolves provider-google directly and populates cache.
	p1 := FindLinkedProvider(ctx, db, got3, "provider-google", nil)
	if p1 == nil || p1.ClientId != "google-client-1" {
		t.Fatalf("FindLinkedProvider exact match = %+v", p1)
	}
	p2 := FindLinkedProvider(ctx, db, got3, "google", nil)
	if p2 == nil || p2.ClientId != "google-client-1" {
		t.Fatalf("FindLinkedProvider type match = %+v", p2)
	}

	// InvalidateApplication evicts both L1 and L2 so updates are immediately visible.
	app.RedirectUris = []string{"https://hanzo.app/auth/callback", "hanzo://oauth/callback"}
	if err := app.UpdateCtx(ctx); err != nil {
		t.Fatalf("update app: %v", err)
	}
	InvalidateApplication(ctx, db, "hanzo-app")
	got4, err := GetApplicationByClientId(ctx, db, "hanzo-app")
	if err != nil || got4 == nil || len(got4.RedirectUris) != 2 {
		t.Fatalf("post-invalidation app = %+v, err=%v", got4, err)
	}

	// InvalidateProvider evicts both L1 and L2.
	prov.ClientId = "google-client-2"
	if err := prov.UpdateCtx(ctx); err != nil {
		t.Fatalf("update provider: %v", err)
	}
	InvalidateProvider(ctx, db, "admin", "provider-google")
	p3, err := GetProvider(ctx, db, "admin", "provider-google")
	if err != nil || p3 == nil || p3.ClientId != "google-client-2" {
		t.Fatalf("post-invalidation provider = %+v, err=%v", p3, err)
	}
}

func BenchmarkFindLinkedProvider(b *testing.B) {
	ctx := context.Background()
	db, err := Open("sqlite", ":memory:", "")
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	prov := orm.New[schema.Provider](db)
	prov.Owner = "admin"
	prov.Name = "provider-google"
	prov.Type = "Google"
	prov.Category = "OAuth"
	prov.ClientId = "cid"
	prov.SetId("admin/provider-google")
	if err := prov.CreateCtx(ctx); err != nil {
		b.Fatalf("create provider: %v", err)
	}

	app := orm.New[schema.Application](db)
	app.Owner = "admin"
	app.Name = "hanzo-app"
	app.ClientId = "hanzo-app"
	app.Organization = "hanzo"
	app.Providers = []*schema.ProviderItem{
		{Name: "provider-google", CanSignUp: true, CanSignIn: true},
	}
	app.SetId("admin/hanzo-app")
	if err := app.CreateCtx(ctx); err != nil {
		b.Fatalf("create app: %v", err)
	}

	b.Run("uncached_db", func(b *testing.B) {
		DisableCache()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			a, err := GetApplicationByClientId(ctx, db, "hanzo-app")
			if err != nil || a == nil {
				b.Fatalf("app err=%v", err)
			}
			if p := FindLinkedProvider(ctx, db, a, "provider-google", nil); p == nil {
				b.Fatal("provider nil")
			}
		}
	})
	b.Run("cached_L1", func(b *testing.B) {
		EnableCache(time.Minute, nil)
		defer DisableCache()
		a0, _ := GetApplicationByClientId(ctx, db, "hanzo-app")
		_ = FindLinkedProvider(ctx, db, a0, "provider-google", nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			a, err := GetApplicationByClientId(ctx, db, "hanzo-app")
			if err != nil || a == nil {
				b.Fatalf("app err=%v", err)
			}
			if p := FindLinkedProvider(ctx, db, a, "provider-google", nil); p == nil {
				b.Fatal("provider nil")
			}
		}
	})
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hanzoai/orm"
	kv "github.com/hanzokv/go/v9"

	"github.com/hanzoai/iam/pkg/schema"
)

// KV is an optional distributed key-value cache (e.g. Hanzo KV / Valkey) shared
// across IAM replicas. Implementations must be safe for concurrent use and
// fail-open (return ok=false on transient errors) so a cache outage never blocks
// authentication.
type KV interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration)
	Del(ctx context.Context, keys ...string)
}

// HanzoKV adapts a github.com/hanzokv/go/v9 client to the store.KV interface.
// Every operation uses a tight timeout so a degraded KV pod never stalls login.
type HanzoKV struct {
	client  kv.UniversalClient
	prefix  string
	timeout time.Duration
}

// NewHanzoKV wraps an existing Hanzo KV client with a namespace prefix
// (defaulting to "iam:v1:").
func NewHanzoKV(client kv.UniversalClient, prefix string) *HanzoKV {
	if client == nil {
		return nil
	}
	if prefix == "" {
		prefix = "iam:v1:"
	}
	return &HanzoKV{
		client:  client,
		prefix:  prefix,
		timeout: 50 * time.Millisecond,
	}
}

// OpenKV connects to a Hanzo KV / Valkey / Redis endpoint (supporting kv://,
// kvs://, valkey://, redis://, rediss://) and returns a ready KV adapter.
func OpenKV(ctx context.Context, rawURL string) (*HanzoKV, error) {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return nil, fmt.Errorf("store: empty KV URL")
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("store: invalid KV URL: %w", err)
	}
	switch parsed.Scheme {
	case "kv", "valkey":
		parsed.Scheme = "redis"
	case "kvs", "valkeys":
		parsed.Scheme = "rediss"
	}
	opts, err := kv.ParseURL(parsed.String())
	if err != nil {
		return nil, fmt.Errorf("store: parse KV URL: %w", err)
	}
	opts.DialTimeout = 2 * time.Second
	opts.ReadTimeout = 200 * time.Millisecond
	opts.WriteTimeout = 200 * time.Millisecond
	client := kv.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("store: ping KV: %w", err)
	}
	return NewHanzoKV(client, "iam:v1:"), nil
}

// Close closes the underlying Hanzo KV connection pool.
func (h *HanzoKV) Close() error {
	if h == nil || h.client == nil {
		return nil
	}
	return h.client.Close()
}

func (h *HanzoKV) Get(ctx context.Context, key string) ([]byte, bool) {
	if h == nil || h.client == nil {
		return nil, false
	}
	c, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	b, err := h.client.Get(c, h.prefix+key).Bytes()
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

func (h *HanzoKV) Set(ctx context.Context, key string, val []byte, ttl time.Duration) {
	if h == nil || h.client == nil || len(val) == 0 || ttl <= 0 {
		return
	}
	c, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	_ = h.client.Set(c, h.prefix+key, val, ttl).Err()
}

func (h *HanzoKV) Del(ctx context.Context, keys ...string) {
	if h == nil || h.client == nil || len(keys) == 0 {
		return
	}
	prefixed := make([]string, len(keys))
	for i, k := range keys {
		prefixed[i] = h.prefix + k
	}
	c, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	_ = h.client.Del(c, prefixed...).Err()
}

// --- L1 + L2 Hot-Read Cache for Applications & Providers ---

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

type hotCache struct {
	ttl time.Duration
	l2  KV
	mu  sync.RWMutex
	l1  map[string]cacheEntry
}

var (
	activeCache atomic.Pointer[hotCache]
	sharedKV    atomic.Pointer[kvBox]
)

type kvBox struct {
	kv KV
}

// DefaultCacheTTL is the default L1/L2 TTL for hot Application and Provider
// lookups on the OAuth authorize / auth-methods path. Writes through IAM's
// CRUD handlers invalidate immediately; the TTL bounds staleness across
// out-of-band DB edits or multi-replica writes.
const DefaultCacheTTL = 60 * time.Second

// UseKV installs a shared L2 KV store for both store hot-reads (applications,
// providers) and OIDC federation caches (IdP discovery, JWKS). Calling UseKV(nil)
// clears the L2 backend while preserving any L1 cache configuration.
func UseKV(l2 KV) {
	if l2 == nil {
		sharedKV.Store(nil)
	} else {
		sharedKV.Store(&kvBox{kv: l2})
	}
	if cur := activeCache.Load(); cur != nil {
		EnableCache(cur.ttl, l2)
	}
}

// SharedKV returns the currently installed distributed KV backend, or nil.
func SharedKV() KV {
	if b := sharedKV.Load(); b != nil {
		return b.kv
	}
	return nil
}

// EnableCache activates the L1 in-memory + optional L2 KV cache for hot store
// reads (GetApplicationByClientId, GetProvider). A zero or negative ttl
// disables the cache.
func EnableCache(ttl time.Duration, l2 KV) {
	if ttl <= 0 {
		activeCache.Store(nil)
		return
	}
	if l2 != nil {
		sharedKV.Store(&kvBox{kv: l2})
	} else if b := sharedKV.Load(); b != nil {
		l2 = b.kv
	}
	activeCache.Store(&hotCache{
		ttl: ttl,
		l2:  l2,
		l1:  make(map[string]cacheEntry),
	})
}

// DisableCache turns off the store hot-read cache (used by tests or explicit
// IAM_CACHE_TTL=0 opt-outs).
func DisableCache() {
	activeCache.Store(nil)
}

func (c *hotCache) get(ctx context.Context, l1Key, l2Key string) ([]byte, bool) {
	now := time.Now()
	c.mu.RLock()
	e, ok := c.l1[l1Key]
	c.mu.RUnlock()
	if ok && now.Before(e.expiresAt) {
		return e.data, true
	}
	if c.l2 != nil {
		if b, hit := c.l2.Get(ctx, l2Key); hit {
			c.setL1(l1Key, b, now.Add(c.ttl))
			return b, true
		}
	}
	return nil, false
}

func (c *hotCache) set(ctx context.Context, l1Key, l2Key string, data []byte) {
	if len(data) == 0 {
		return
	}
	c.setL1(l1Key, data, time.Now().Add(c.ttl))
	if c.l2 != nil {
		c.l2.Set(ctx, l2Key, data, c.ttl)
	}
}

func (c *hotCache) setL1(l1Key string, data []byte, exp time.Time) {
	c.mu.Lock()
	if len(c.l1) > 4096 {
		now := time.Now()
		for k, v := range c.l1 {
			if now.After(v.expiresAt) {
				delete(c.l1, k)
			}
		}
	}
	c.l1[l1Key] = cacheEntry{data: data, expiresAt: exp}
	c.mu.Unlock()
}

func (c *hotCache) del(ctx context.Context, l1Key, l2Key string) {
	c.mu.Lock()
	delete(c.l1, l1Key)
	c.mu.Unlock()
	if c.l2 != nil {
		c.l2.Del(ctx, l2Key)
	}
}

func dbKeyPrefix(db orm.DB) string {
	return fmt.Sprintf("%p:", db)
}

func appCacheKeys(db orm.DB, clientId string) (l1Key, l2Key string) {
	l2Key = "app:cid:" + clientId
	return dbKeyPrefix(db) + l2Key, l2Key
}

func providerCacheKeys(db orm.DB, owner, name string) (l1Key, l2Key string) {
	l2Key = "prov:" + owner + "/" + name
	return dbKeyPrefix(db) + l2Key, l2Key
}

// InvalidateApplication evicts cached application lookups for each given
// clientId from both L1 memory and L2 KV. Safe to call when caching is disabled.
func InvalidateApplication(ctx context.Context, db orm.DB, clientIds ...string) {
	c := activeCache.Load()
	if c == nil {
		return
	}
	for _, cid := range clientIds {
		if cid == "" {
			continue
		}
		l1Key, l2Key := appCacheKeys(db, cid)
		c.del(ctx, l1Key, l2Key)
	}
}

// InvalidateProvider evicts a cached provider lookup from both L1 memory and L2
// KV. Safe to call when caching is disabled.
func InvalidateProvider(ctx context.Context, db orm.DB, owner, name string) {
	c := activeCache.Load()
	if c == nil || name == "" {
		return
	}
	if owner == "" {
		owner = "admin"
	}
	l1Key, l2Key := providerCacheKeys(db, owner, name)
	c.del(ctx, l1Key, l2Key)
}

func cachedGetAppByClientId(ctx context.Context, db orm.DB, clientId string) (*schema.Application, bool) {
	c := activeCache.Load()
	if c == nil || clientId == "" {
		return nil, false
	}
	l1Key, l2Key := appCacheKeys(db, clientId)
	raw, ok := c.get(ctx, l1Key, l2Key)
	if !ok {
		return nil, false
	}
	var app schema.Application
	if err := json.Unmarshal(raw, &app); err != nil {
		return nil, false
	}
	app.Init(db)
	return &app, true
}

func cachePutAppByClientId(ctx context.Context, db orm.DB, clientId string, app *schema.Application) {
	c := activeCache.Load()
	if c == nil || clientId == "" || app == nil {
		return
	}
	// Strip transient enriched provider pointers before marshaling so we never
	// cache stale Provider sub-documents inside an Application entry.
	copyApp := *app
	if len(app.Providers) > 0 {
		copyApp.Providers = make([]*schema.ProviderItem, len(app.Providers))
		for i, item := range app.Providers {
			if item == nil {
				continue
			}
			it := *item
			it.Provider = nil
			copyApp.Providers[i] = &it
		}
	}
	raw, err := json.Marshal(&copyApp)
	if err != nil {
		return
	}
	l1Key, l2Key := appCacheKeys(db, clientId)
	c.set(ctx, l1Key, l2Key, raw)
}

func cachedGetProvider(ctx context.Context, db orm.DB, owner, name string) (*schema.Provider, bool) {
	c := activeCache.Load()
	if c == nil || owner == "" || name == "" {
		return nil, false
	}
	l1Key, l2Key := providerCacheKeys(db, owner, name)
	raw, ok := c.get(ctx, l1Key, l2Key)
	if !ok {
		return nil, false
	}
	var p schema.Provider
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, false
	}
	p.Init(db)
	return &p, true
}

func cachePutProvider(ctx context.Context, db orm.DB, owner, name string, p *schema.Provider) {
	c := activeCache.Load()
	if c == nil || owner == "" || name == "" || p == nil {
		return
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return
	}
	l1Key, l2Key := providerCacheKeys(db, owner, name)
	c.set(ctx, l1Key, l2Key, raw)
}

// FindLinkedProvider resolves a single sign-in-enabled provider link on app
// matching name (by exact record name first, falling back to case-insensitive
// provider type), filtering candidates with accept when non-nil. On an exact
// link-name match (the standard case for `provider=provider-google`), this
// performs 1 lookup instead of N+1 queries across every linked provider.
func FindLinkedProvider(ctx context.Context, db orm.DB, app *schema.Application, name string, accept func(*schema.Provider) bool) *schema.Provider {
	if app == nil || name == "" {
		return nil
	}
	allowed := func(p *schema.Provider) bool {
		return p != nil && (accept == nil || accept(p))
	}
	// Fast path: exact link name match (e.g. "provider-google").
	for _, item := range app.Providers {
		if item == nil || !item.CanSignIn || item.Name != name {
			continue
		}
		p := item.Provider
		if p == nil {
			var err error
			p, err = GetProvider(ctx, db, ProviderOwner(item), item.Name)
			if err == nil && p != nil {
				item.Provider = p
			}
		}
		if allowed(p) {
			return p
		}
	}
	// Fallback: resolve sign-in links by provider type (e.g. "google").
	for _, item := range app.Providers {
		if item == nil || !item.CanSignIn || item.Name == "" {
			continue
		}
		p := item.Provider
		if p == nil {
			var err error
			p, err = GetProvider(ctx, db, ProviderOwner(item), item.Name)
			if err != nil || p == nil {
				continue
			}
			item.Provider = p
		}
		if allowed(p) && strings.EqualFold(p.Type, name) {
			return p
		}
	}
	return nil
}

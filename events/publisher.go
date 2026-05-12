// Copyright 2021 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package events publishes domain events from IAM onto the Hanzo bus.
//
// Transport: NATS. Subjects are flat, single-noun-qualified strings (e.g.
// "org.created"). Payloads are JSON. Failures are best-effort: the DB
// commit is authoritative; downstream provisioning is expected to be
// idempotent and re-triggerable.
package events

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/beego/beego/v2/core/logs"
	"github.com/nats-io/nats.go"
)

// DefaultURL is the in-cluster NATS endpoint used when NATS_URL is unset.
const DefaultURL = "nats://nats:4222"

// Publisher publishes domain events from IAM. The generic Publish
// method accepts any subject+payload; typed helpers (PublishOrgCreated,
// ...) wrap it for known event shapes so callers do not hand-roll
// subject strings.
type Publisher interface {
	Publish(ctx context.Context, subject string, payload any) error
	PublishOrgCreated(ctx context.Context, c Created) error
	Close()
}

// NATS is the canonical Publisher. A nil *NATS is a valid no-op publisher
// (returned by New when NATS is unavailable) — every method on it logs a
// warning and returns without error so callers never need a nil check.
type NATS struct {
	mu   sync.RWMutex
	conn *nats.Conn
}

// defaultPub is the process-wide Publisher, lazily constructed on first
// Default() call. Tests should construct their own via New() instead of
// touching this directly.
var (
	defaultPub  Publisher
	defaultOnce sync.Once
)

// Default returns the process-wide Publisher, dialed once on first
// access. Safe to call from request handlers.
func Default() Publisher {
	defaultOnce.Do(func() {
		defaultPub = New()
	})
	return defaultPub
}

// New returns a Publisher. NATS_URL controls the endpoint; empty falls
// back to DefaultURL. If the connection cannot be established, New
// returns a *NATS with a nil conn that logs WARN on every Publish.
// New never returns an error — IAM must keep accepting writes when the
// event bus is down.
func New() Publisher {
	url := os.Getenv("NATS_URL")
	if url == "" {
		url = DefaultURL
	}

	conn, err := nats.Connect(
		url,
		nats.Name("hanzo-iam"),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
	)
	if err != nil {
		logs.Warning("events: NATS connect to %s failed: %v — publishing disabled", url, err)
		return &NATS{}
	}

	logs.Info("events: NATS connected to %s", url)
	return &NATS{conn: conn}
}

// Publish marshals payload as JSON and sends it on subject. If the
// underlying connection is nil (degraded mode) or publish fails, the
// error is logged and nil is returned — the caller's write must succeed
// regardless of bus health.
func (n *NATS) Publish(ctx context.Context, subject string, payload any) error {
	if n == nil {
		logs.Warning("events: Publish on nil *NATS (subject=%s)", subject)
		return nil
	}

	n.mu.RLock()
	conn := n.conn
	n.mu.RUnlock()

	if conn == nil {
		logs.Warning("events: skip subject=%s — NATS unavailable", subject)
		return nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logs.Warning("events: marshal subject=%s failed: %v", subject, err)
		return nil
	}

	if err := conn.Publish(subject, body); err != nil {
		logs.Warning("events: publish subject=%s failed: %v", subject, err)
		return nil
	}

	return nil
}

// Close drains and shuts the underlying NATS connection. Safe to call
// on a nil *NATS.
func (n *NATS) Close() {
	if n == nil {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.conn == nil {
		return
	}
	_ = n.conn.Drain()
	n.conn = nil
}

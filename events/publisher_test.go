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

package events

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startServer brings up an embedded NATS server bound to a random
// loopback port and returns the client URL plus a shutdown hook.
func startServer(t *testing.T) (string, func()) {
	t.Helper()

	opts := &natsserver.Options{
		Host:           "127.0.0.1",
		Port:           -1, // pick a free port
		NoLog:          true,
		NoSigs:         true,
		MaxControlLine: 4096,
	}

	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("server not ready")
	}

	return srv.ClientURL(), srv.Shutdown
}

// withURL points os.Getenv("NATS_URL") at url for the duration of fn.
func withURL(t *testing.T, url string, fn func()) {
	t.Helper()
	t.Setenv("NATS_URL", url)
	fn()
}

func TestPublishOrgCreatedRoundTrip(t *testing.T) {
	url, shutdown := startServer(t)
	defer shutdown()

	// Subscribe with a raw client first so we can verify the payload
	// independently of New().
	sub, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("subscriber connect: %v", err)
	}
	defer sub.Close()

	received := make(chan []byte, 1)
	if _, err := sub.Subscribe(SubjectOrgCreated, func(m *nats.Msg) {
		received <- m.Data
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := sub.Flush(); err != nil {
		t.Fatalf("subscriber flush: %v", err)
	}

	var pub Publisher
	withURL(t, url, func() { pub = New() })
	defer pub.Close()

	natsPub, ok := pub.(*NATS)
	if !ok {
		t.Fatalf("New returned %T, want *NATS", pub)
	}

	want := Created{
		ID:         "admin/acme",
		Slug:       "acme",
		Name:       "Acme Inc.",
		OwnerID:    "admin/satoshi",
		OwnerEmail: "satoshi@acme.test",
		TS:         time.Now().UnixMilli(),
	}

	if err := natsPub.PublishOrgCreated(context.Background(), want); err != nil {
		t.Fatalf("PublishOrgCreated: %v", err)
	}

	select {
	case body := <-received:
		var got Created
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal payload: %v\nbody=%s", err, string(body))
		}
		if got != want {
			t.Fatalf("payload mismatch:\n got=%+v\nwant=%+v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for org.created delivery")
	}
}

func TestPublishWithoutServerIsNoOp(t *testing.T) {
	// Point at a port nothing is listening on. RetryOnFailedConnect
	// + MaxReconnects(-1) means Connect returns successfully and the
	// client retries in the background — Publish degrades to a logged
	// warning, not an error.
	t.Setenv("NATS_URL", "nats://127.0.0.1:1")

	pub := New()
	defer pub.Close()

	err := pub.Publish(context.Background(), SubjectOrgCreated, Created{
		ID:   "admin/acme",
		Slug: "acme",
		Name: "Acme Inc.",
		TS:   time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("Publish must never return an error to callers, got: %v", err)
	}
}

func TestNilNATSPublisherIsNoOp(t *testing.T) {
	var n *NATS
	if err := n.Publish(context.Background(), SubjectOrgCreated, Created{}); err != nil {
		t.Fatalf("nil *NATS Publish must be no-op, got: %v", err)
	}
	n.Close() // must not panic
}

func TestSubjectIsExact(t *testing.T) {
	if SubjectOrgCreated != "org.created" {
		t.Fatalf("subject drift: got %q, want %q", SubjectOrgCreated, "org.created")
	}
}

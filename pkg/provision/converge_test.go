// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package provision

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const convergeDoc = `
orgs:
  - name: hanzo
    displayName: Hanzo
    apps:
      - { app: cloud, type: confidential, hosts: [cloud.hanzo.ai] }
`

// One pass reports each client and a summary, and fails when an item fails.
func TestConvergeReportsAndFails(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"status":"ok","action":"updated"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"error","msg":"booting"}`))
	}))
	defer srv.Close()
	r := &Reconciler{BaseURL: srv.URL, Token: "tok"}

	var out bytes.Buffer
	if err := Converge(context.Background(), r, []byte(convergeDoc), &out); err != nil {
		t.Fatalf("Converge: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "hanzo-cloud") || !strings.Contains(out.String(), "1 app(s), 0 account(s), 0 failed") {
		t.Fatalf("report:\n%s", out.String())
	}

	status = http.StatusServiceUnavailable
	out.Reset()
	if err := Converge(context.Background(), r, []byte(convergeDoc), &out); err == nil {
		t.Fatalf("a failed upsert converged:\n%s", out.String())
	}
}

// A writing pass with no service token refuses before it writes anything.
func TestConvergeRequiresToken(t *testing.T) {
	err := Converge(context.Background(), &Reconciler{BaseURL: "http://127.0.0.1:1"}, []byte(convergeDoc), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "service token") {
		t.Fatalf("got %v, want the missing-token refusal", err)
	}
}

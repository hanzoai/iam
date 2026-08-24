// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package routes_test

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
)

// EVERY AUTO-MOUNTED CONTROL DOOR REQUIRES A BEARER.
//
// zip projects the typed-op registry onto framework-owned addresses at Build —
// the OpenAPI document, the docs UI, the GraphQL endpoint, the plugin
// declaration, the MCP server, and the by-name op-call plane. None is a route any
// group holds, so a group's Guard cannot reach them; authz.Control, mounted
// depth-0, is the one seam that can. Each dispatches into the SAME admin CRUD the
// REST surface exposes, so a door left ungated is that CRUD reached
// unauthenticated over another transport.
//
// The assertion is 401 on every door with no credential. A status code is enough
// here precisely because these carry no body an anonymous caller may read: the
// point is that the request never reaches the op behind the door.
func TestControlDoors_RequireABearer(t *testing.T) {
	app, _ := embedded(t)

	// The call plane gates on the path PREFIX, before it resolves the op name, so any
	// suffix proves the door: a request never reaches dispatch to a read op.
	doors := []struct {
		method, path string
	}{
		{"POST", "/mcp"},
		{"GET", zip.SpecPath},
		{"GET", zip.DocsPath},
		{"GET", zip.GraphPath},
		{"POST", zip.GraphPath},
		{"GET", zip.PluginPath},
		{"POST", zip.CallPath + "iam_users"},
	}

	for _, d := range doors {
		t.Run(d.method+" "+d.path, func(t *testing.T) {
			var body io.Reader
			if d.method == "POST" {
				body = bytes.NewReader([]byte("{}"))
			}
			req := httptest.NewRequest(d.method, d.path, body)
			req.Host = "hanzo.id"
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := testhttp.Do(app, req)
			if err != nil {
				t.Fatalf("%s %s: %v", d.method, d.path, err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Fatalf("%s %s unauthenticated = %d, want 401 — the door is not gated: %s",
					d.method, d.path, resp.StatusCode, b)
			}
		})
	}
}

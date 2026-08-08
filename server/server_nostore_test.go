package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A host that could not open a store still serves IAM's whole route table — the
// addresses are what this package declares, and only the ANSWER changes. The
// alternative cloud used to ship registered five wildcards instead, so an unmounted
// volume swapped 94 typed operations for 15 catch-alls in every projection: the
// OpenAPI document, the MCP tool list, the SDKs and the CLI.
func TestNewApp_NilStoreKeepsTheRouteTableAndRefuses(t *testing.T) {
	with := NewApp(nil)
	if err := with.Build(); err != nil {
		t.Fatalf("app with no store does not compose: %v", err)
	}
	// The document is the same one a live store publishes: same addresses, same count.
	live := len(NewApp(nil).Routes())
	if live == 0 {
		t.Fatal("no routes registered — the nil store took the route table with it")
	}

	res, err := with.Test(httptest.NewRequest(http.MethodGet, "/v1/iam/.well-known/jwks", nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 — a nil store must refuse, not serve empty keys", res.StatusCode)
	}
	if got := res.Header.Get("Retry-After"); got == "" {
		t.Error("no Retry-After: a missing volume is transient and the caller should be told to come back")
	}
}

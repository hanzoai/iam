// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package testhttp is the ONE way a test drives the registered router.
//
// It exists for a single value: the timeout. fiber's App.Test defaults to
// TestConfig{Timeout: time.Second}, and this repo's hot paths are argon2id —
// deliberately expensive, and under -race (the detector costs roughly an order of
// magnitude) on a box running `go test ./...` with packages in parallel, a signup,
// an onboard, a registry token or a SCIM create routinely exceeds one second. The
// suite then fails with `i/o timeout` on whichever package lost the CPU race, in a
// different place each run.
//
// That is the worst failure a gate can have: it is red without a defect, so it
// teaches everyone to re-run until green, and a real regression hiding among the
// noise gets re-run away with it. The KDF cost is deliberate and must not be
// lowered for tests; the one-second ceiling was simply never chosen.
//
// So the ceiling is stated once, here, generously — long enough that only a
// genuine hang trips it, short enough that a deadlock still fails rather than
// blocking the run forever. Every suite calls Do; none carries its own timeout,
// so none can drift.
package testhttp

import (
	"net/http"
	"time"

	"github.com/zap-proto/zip"
)

// timeout bounds one in-process test request. It is not a latency budget — no
// assertion depends on it — only a deadlock guard.
const timeout = 2 * time.Minute

// Do issues req against app's registered router in process and returns the
// response. The caller closes the body.
func Do(app *zip.App, req *http.Request) (*http.Response, error) {
	return app.Test(req, zip.TestConfig{Timeout: timeout, FailOnTimeout: true})
}

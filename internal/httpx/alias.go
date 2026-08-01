// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package httpx

import "github.com/zap-proto/zip"

// Alias registers h at the canonical address AND at the legacy spelling it
// replaced, with the given method.
//
// A path segment names a THING; the HTTP method says what is being done to it.
// The verb-noun addresses this service inherited (`send-verification-code`,
// `set-preferred-mfa`, …) say the verb twice, and they are what a customer reads
// in `hanzo iam --help`, in every generated SDK method name and on every docs
// page. The canonical noun is what the published document declares; the legacy
// spelling stays reachable so a pinned consumer does not break.
//
// ONE handler value, TWO addresses — there is no second implementation to keep
// in step and no forward that could answer differently from the thing it
// forwards to. When the last pinned consumer moves, the legacy half is deleted
// and nothing else changes.
func Alias(reg func(string, ...zip.Handler) zip.Router, canonical, legacy string, h zip.Handler) {
	reg(canonical, h)
	reg(legacy, h)
}

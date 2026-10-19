// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/hanzoai/outbound"
)

// Every identity-provider call rides federationHTTPClient, and the provider URLs
// it dials are configuration a tenant admin writes (IssuerUrl, Custom*Url). The
// client is hanzoai/outbound's: the address is judged at the dial, so each of
// these is refused before a byte leaves — including the forms the guard this
// replaced admitted (NAT64 and 6to4 spellings of the metadata endpoint, Oracle's
// and Alibaba's metadata, the benchmarking and documentation blocks, 240/4).
func TestFederationClientRefusesNonPublicAddresses(t *testing.T) {
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://[64:ff9b::a9fe:a9fe]/latest/meta-data/",
		"http://[2002:a9fe:a9fe::1]/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://192.0.0.192/opc/v2/instance/",
		"http://198.18.0.1/",
		"http://240.0.0.1/",
		"http://127.0.0.1:1/",
		"http://10.0.0.1/",
		"http://localhost:1/",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		resp, err := federationHTTPClient.Do(req)
		cancel()
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, outbound.ErrRefused) {
			t.Errorf("GET %s: err = %v, want outbound.ErrRefused", u, err)
		}
	}
}

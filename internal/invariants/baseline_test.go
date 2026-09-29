// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invariants_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/hanzoai/iam/internal/invariants"
)

// The ledger only shrinks. baseline.json is every row's Known list as HIP-0527
// phase 1 left it; a Known entry the baseline does not hold — a row that grew,
// or a new row that starts with violations — fails here, so recording a
// violation takes a change to this file that a reviewer sees on its own.
func TestAdminNamespaceInvariants_ledgerNeverGrows(t *testing.T) {
	raw, err := os.ReadFile("baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var base map[string][]string
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	for key, r := range invariants.Ledger {
		for _, k := range r.Known {
			if !slices.Contains(base[key], k) {
				t.Errorf("%s gained %q, which the baseline does not hold", key, k)
			}
		}
	}
}

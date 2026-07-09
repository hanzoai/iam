// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package object

import "testing"

// TestHasUnresolvedSecret pins the fail-closed predicate that initDefinedUser
// uses to refuse creating a user whose password is still a ${SECRET} placeholder
// (backing KMS/env secret missing at boot). A resolved plaintext or a real
// argon2id/bcrypt hash must NOT be flagged; a surviving ${NAME} must be.
func TestHasUnresolvedSecret(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"resolved plaintext", "***REMOVED***", false},
		{"argon2id hash", "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$aGFzaA", false},
		{"bcrypt hash", "$2a$10$.MSmG5LLwAsc9p0HmWNErOIWlM01jNn8LUIt0DUPi42k8bwgI/bAq", false},
		{"empty", "", false},
		{"literal dollar-brace but not a placeholder", "price is ${} today", false},
		{"unresolved placeholder", "${ADMIN_SUPERADMIN_SEED_PASSWORD}", true},
		{"unresolved placeholder embedded", "prefix-${IAM_GITHUB_CLIENT_SECRET}-suffix", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasUnresolvedSecret(c.in); got != c.want {
				t.Fatalf("hasUnresolvedSecret(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

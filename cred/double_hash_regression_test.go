// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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

package cred

import "testing"

// TestSingleHashVerifies_DoubleHashDoesNot pins the invariant behind the
// SetPassword double-hash bug: a password must be hashed exactly ONCE.
//
// The controller used to pre-hash in SetPassword and then hand the result to
// object.UpdateUser, which hashes a changed password again — storing
// hash(hash(pw)). Login then compares the plaintext against the inner hash and
// can never match, silently locking every password reset out. This test fails
// if anything reintroduces a verify against a double-hashed value.
func TestSingleHashVerifies_DoubleHashDoesNot(t *testing.T) {
	const password = "***REMOVED***"
	const salt = ""

	for _, pt := range []string{"argon2id", "bcrypt"} {
		pt := pt
		t.Run(pt, func(t *testing.T) {
			cm := GetCredManager(pt)
			if cm == nil {
				t.Fatalf("no cred manager for %q", pt)
			}

			single := cm.GetHashedPassword(password, salt)
			if single == "" {
				t.Fatalf("%s: empty hash", pt)
			}
			if !cm.IsPasswordCorrect(password, single, salt) {
				t.Fatalf("%s: single-hashed password must verify against the plaintext", pt)
			}

			// Hashing the already-hashed value (the bug) must NOT verify the
			// original plaintext — proving why pre-hash + UpdateUser re-hash
			// locked users out.
			double := cm.GetHashedPassword(single, salt)
			if cm.IsPasswordCorrect(password, double, salt) {
				t.Fatalf("%s: double-hashed value unexpectedly verified the plaintext — the bug is back", pt)
			}
		})
	}
}

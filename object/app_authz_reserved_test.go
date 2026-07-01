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

//go:build !skipCi

// V5/Red#4 — capability name-collision. AppNameIsCapabilityReserved backs the
// getUsernameByClientIdSecret guard that stops a customer from registering
// <theirOrg>/<cap-app-name> to inherit a platform app's capability. Pure:
// conf.GetConfigString reads os env first, so no DB/config file is needed.

package object

import (
	"os"
	"testing"
)

func TestAppNameIsCapabilityReserved(t *testing.T) {
	// Snapshot + restore the two allowlists this test drives.
	for _, k := range []string{"IAM_USER_ADMIN_APPS", "IAM_KEY_MINT_ALLOWED_APPS"} {
		if old, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { os.Setenv(k, old) })
		} else {
			t.Cleanup(func() { os.Unsetenv(k) })
		}
	}
	os.Setenv("IAM_USER_ADMIN_APPS", "hanzo-console,lux-console,zoo-console,pars-console,hanzo-cloud")
	os.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console,hanzo-chat")

	reserved := []string{"hanzo-console", "hanzo-cloud", "hanzo-chat", "lux-console", "pars-console"}
	for _, name := range reserved {
		if !AppNameIsCapabilityReserved(name) {
			t.Fatalf("%q MUST be capability-reserved (a customer app with this Name must be refused a principal)", name)
		}
	}

	notReserved := []string{"", "maxpower-app", "maxpower-console", "hanzo-random", "hanzo-ai", "console"}
	for _, name := range notReserved {
		if AppNameIsCapabilityReserved(name) {
			t.Fatalf("%q must NOT be capability-reserved (would wrongly block a legitimate tenant app)", name)
		}
	}

	// A name is reserved iff it appears in some allowlist — dropping the
	// allowlist must free the name (no phantom reservations).
	os.Setenv("IAM_USER_ADMIN_APPS", "")
	os.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "")
	if AppNameIsCapabilityReserved("hanzo-console") {
		t.Fatal("with empty allowlists, no name is reserved")
	}
}

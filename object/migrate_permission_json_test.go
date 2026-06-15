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

package object

import "testing"

// TestNormalizePgArrayLiteral pins the repair behavior for Postgres
// array-literal residue in JSON-backed []string columns. The two cases
// that actually crashed production are {admin/*} and {iam}; the {} case
// is the subtle one (valid JSON *object* but invalid as a []string).
func TestNormalizePgArrayLiteral(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		changed bool
	}{
		{`{admin/*}`, `["admin/*"]`, true},                              // live corruption (permission-iam.users)
		{`{iam}`, `["iam"]`, true},                                      // live corruption (permission-iam.resources)
		{`{a,b}`, `["a","b"]`, true},                                    // multi-element PG array
		{`{}`, `[]`, true},                                              // empty PG array (valid JSON object, invalid []string)
		{`{"x","y"}`, `["x","y"]`, true},                                // PG array with quoted elements
		{`["admin/*"]`, `["admin/*"]`, false},                           // already valid JSON array: untouched
		{`["Read","Write","Admin"]`, `["Read","Write","Admin"]`, false}, // already valid: untouched
		{`[]`, `[]`, false},                                             // valid empty JSON array: untouched
		{`null`, `null`, false},                                         // valid JSON null: untouched
		{``, ``, false},                                                 // empty string: untouched
		{`[null]`, `[null]`, false},                                     // valid JSON array: untouched
	}
	for _, c := range cases {
		got, changed := normalizePgArrayLiteral(c.in)
		if got != c.want || changed != c.changed {
			t.Errorf("normalizePgArrayLiteral(%q) = (%q,%v), want (%q,%v)", c.in, got, changed, c.want, c.changed)
		}
	}
}

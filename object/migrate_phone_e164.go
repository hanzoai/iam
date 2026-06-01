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

import (
	"fmt"
	"strings"

	"github.com/hanzoai/iam/util"
	"github.com/hanzoai/xorm"
)

// MigratePhoneToE164 walks every user row whose `phone` does not start
// with '+' and rewrites it to its canonical E.164 form using the
// adjacent `country_code` column. Idempotent — re-running it is a
// cheap no-op once every row is already E.164.
//
// Rows whose `(phone, country_code)` pair cannot be parsed by
// libphonenumber are LEFT UNCHANGED and logged. Those are typically
// fixture rows (e.g. `1337000001`, `9999999999`) that were never real
// dialable numbers; they continue to be reachable via the by-attribute
// endpoint's literal fallback, but they will not collide with new
// E.164 writes.
//
// Schema change: NONE. The migration mutates row values inside the
// existing `phone` VARCHAR column; no DDL is required.
//
// Returns (updated, skipped, error). `updated` is the count of rows
// whose phone was rewritten to E.164. `skipped` is the count of rows
// whose phone could not be parsed and was left alone.
func MigratePhoneToE164(engine *xorm.Engine) (updated, skipped int, err error) {
	if engine == nil {
		return 0, 0, fmt.Errorf("MigratePhoneToE164: nil engine")
	}

	// Pull every row that hasn't been normalized yet. The
	// `phone NOT LIKE '+%'` predicate is a cheap filter that lets the
	// migration run on every boot without scanning E.164 rows.
	var rows []User
	err = engine.
		Where("phone IS NOT NULL").
		And("phone != ''").
		And("phone NOT LIKE '+%'").
		Cols("owner", "name", "phone", "country_code").
		Find(&rows)
	if err != nil {
		return 0, 0, fmt.Errorf("MigratePhoneToE164: scan: %w", err)
	}

	for _, r := range rows {
		e164, normErr := util.NormalizeE164(r.Phone, r.CountryCode)
		if normErr != nil || e164 == "" {
			skipped++
			// One-line trace per skipped row so an operator can grep
			// for them during a manual reconcile. Phone is masked.
			fmt.Printf("[migrate-phone-e164] skip owner=%s name=%s phone=%s country=%s reason=%v\n",
				r.Owner, r.Name, util.GetMaskedPhone(r.Phone), r.CountryCode, normErr)
			continue
		}
		if e164 == r.Phone {
			// Already-canonical bypass: a value like "+1..." that
			// snuck past our predicate via a non-leading '+' would
			// fall here. Shouldn't happen given the WHERE clause but
			// the guard makes the loop idempotent under any input.
			continue
		}

		// UPDATE strictly by primary key (owner, name) so we don't
		// touch any row whose phone has been concurrently rewritten.
		_, uErr := engine.
			Where("owner = ? AND name = ?", r.Owner, r.Name).
			Cols("phone").
			Update(&User{Phone: e164})
		if uErr != nil {
			return updated, skipped, fmt.Errorf("MigratePhoneToE164: update %s/%s: %w",
				r.Owner, r.Name, uErr)
		}
		updated++
	}

	if updated > 0 || skipped > 0 {
		fmt.Printf("[migrate-phone-e164] engine=%s updated=%d skipped=%d\n",
			engineLabel(engine), updated, skipped)
	}

	return updated, skipped, nil
}

// engineLabel pulls a short identifier out of an xorm engine for the
// migration log line. SQLite returns the DSN-derived file path; other
// drivers return the driver name. Best-effort; the migration does not
// depend on this string.
func engineLabel(engine *xorm.Engine) string {
	if engine == nil {
		return "<nil>"
	}
	if dsn := engine.DataSourceName(); dsn != "" {
		// Strip query params off SQLite DSNs so the log line stays
		// concise and doesn't leak journal_mode etc.
		if i := strings.Index(dsn, "?"); i > 0 {
			return dsn[:i]
		}
		return dsn
	}
	return engine.DriverName()
}

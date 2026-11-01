// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// TextTally is one texting budget's counter for one bucket in one window: how
// many requests have been admitted against it, kept as a row so admitting one
// reads one row instead of counting the ledger (internal/otp).
//
// The ledger (schema.Text) says WHAT was asked and remains the record; this says
// HOW MANY, which is the only question a budget asks. Counting the ledger meant a
// scan inside the write transaction: every admission walked the window's rows and
// every refusal walked all of them, so the cost of asking for a code grew with the
// abuse it was there to stop, on a store with one writer.
//
// A row is one window, never reused: a new window is a new row, so no update has to
// reset anything and two replicas cannot disagree about where a window starts. The
// bucket is a name the caller cannot choose — a keyed digest of a number or a
// network, or an application's or organization's own id — and it is not customer
// data: like the ledger it stores no number and no address.
//
// Only internal/otp writes it, and no route reads or writes it.
type TextTally struct {
	orm.Model[TextTally]

	// Bucket is the counter's id: bound name, bucket and window start, for
	// example "client/<digest>@1767225600". It is the row's Name.
	Bucket string `json:"bucket" orm:"index"`
	// Window is the first second of the window this row counts, in Unix
	// seconds. A row older than its window is garbage; the sweep in internal/otp
	// removes it.
	Window int64 `json:"window" orm:"index"`
	// Count is how many requests this bucket has admitted in this window.
	Count int `json:"count"`
}

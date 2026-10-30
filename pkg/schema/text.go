// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Text is one request to text a code to a phone number, admitted under the
// texting budgets (internal/otp). The rows are the ledger those budgets count,
// and a row asked with the SMS consent ticked is the record of that opt-in: when,
// for which number, at which application.
//
// It stores no number and no client address. Number and Client are keyed
// digests (internal/otp digest), so the ledger can count a number or a network
// without being able to name either. A row is written for every admitted
// request, whether or not a text went out, so the ledger reads the same for a
// number an account holds and for one nobody holds.
//
// Only internal/otp writes it, and no route reads or writes it: it is not
// customer data and not an audit row a tenant may edit.
type Text struct {
	orm.Model[Text]

	// Owner is the organization the code is sent as, which is the account the
	// carrier bills.
	Owner string `json:"owner" orm:"index"`
	// Name is the row's random id.
	Name string `json:"name"`
	// Time is when the request was admitted, in Unix seconds.
	Time int64 `json:"time" orm:"index"`
	// Application is the application the code was asked for ("owner/name"), or
	// "" for a second factor, which no application asks for.
	Application string `json:"application,omitempty" orm:"index"`
	// Client is the keyed digest of the asking client's network: its IPv4
	// address, or its IPv6 /64.
	Client string `json:"client" orm:"index"`
	// Number is the keyed digest of the destination number.
	Number string `json:"number" orm:"index"`
	// The three flags are stored even when false: the budgets filter on them,
	// and a field a row leaves out matches no comparison.
	//
	// Sent says a text went out: an account holds the number, or the signed-in
	// person asking is adding it. It is what the money budgets count.
	Sent bool `json:"sent"`
	// Factor says the code went to an account's own number as its second
	// factor, or to enrol one: asked by somebody who already proved who they
	// are, not by an open request.
	Factor bool `json:"factor"`
	// Consent says the person ticked the SMS consent when they asked.
	Consent bool `json:"consent"`
}

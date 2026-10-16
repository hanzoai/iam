// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package provision

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Converge is one provisioning pass: parse the document, derive its clients,
// upsert them and its accounts through r, and write one line per item to out.
// It is what `iam provision` runs, and what a host embedding IAM runs against
// its own server, so every caller converges and reports a document the same way.
//
// The report is the audit record, so each account line says what the account
// is, what authority it asks for, and whether a credential was delivered —
// "converged", "privileged" and "usable" are three different facts. The admin
// bit is printed for every account, including the false ones: a grant is
// reviewable only beside the accounts that do not have it. The credential
// itself is never printed.
//
// An error means the pass did not converge: the document did not parse or
// derive, no token was given for a writing pass, or some item failed (each is
// on its own line in out).
func Converge(ctx context.Context, r *Reconciler, doc []byte, out io.Writer) error {
	d, err := Parse(doc)
	if err != nil {
		return err
	}
	clients, err := Derive(d)
	if err != nil {
		return err
	}
	if r.Token == "" && !r.DryRun {
		return fmt.Errorf("no service token: pass --token or set IAM_SERVICE_TOKEN")
	}

	var failed int
	for _, res := range r.Apply(ctx, clients) {
		if res.Err != nil {
			failed++
			fmt.Fprintf(out, "  FAIL     %-28s %v\n", res.Client.Name, res.Err)
			continue
		}
		fmt.Fprintf(out, "  %-8s %-28s %s\n", res.Action, res.Client.Name,
			strings.Join(res.Client.RedirectUris, " "))
	}
	// Accounts converge in the SAME pass as the clients: one document, and a
	// half-applied document is the state nobody can reason about.
	accounts := Accounts(d)
	for _, res := range r.ApplyAccounts(ctx, accounts) {
		name := res.Account.Org + "/" + res.Account.Account.Name
		if res.Err != nil {
			failed++
			fmt.Fprintf(out, "  FAIL     %-28s %v\n", name, res.Err)
			continue
		}
		cred := "credential preserved"
		if res.Credential {
			cred = "credential set"
		}
		fmt.Fprintf(out, "  %-8s %-28s %s account, isAdmin=%t, %s\n",
			res.Action, name, res.Account.Account.Type, res.Admin, cred)
	}
	fmt.Fprintf(out, "%d app(s), %d account(s), %d failed\n", len(clients), len(accounts), failed)
	if failed > 0 {
		return fmt.Errorf("%d item(s) did not converge", failed)
	}
	return nil
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Command email_verified_backfill marks User.EmailVerified=true for accounts that
// already proved mailbox control. Default is dry-run (no writes).
//
// See README.md in this directory for criteria. Do not wire into CI.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func main() {
	dry := flag.Bool("dry-run", true, "when true, only print candidates; no writes")
	driver := flag.String("driver", envOr("IAM_DB_DRIVER", "postgres"), "orm driver")
	dsn := flag.String("dsn", os.Getenv("IAM_DB_DSN"), "database DSN (required)")
	org := flag.String("org", "", "optional owner/org filter (recommended for first runs)")
	only := flag.String("only", "", "optional comma-separated owner/name allowlist after dry-run review")
	flag.Parse()

	if *dsn == "" {
		log.Fatal("IAM_DB_DSN (or -dsn) is required")
	}
	db, err := store.Open(*driver, *dsn, "")
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	q := orm.TypedQuery[schema.User](db)
	if *org != "" {
		q = q.Filter("Owner=", *org)
	}
	rows, err := q.GetAll(ctx)
	if err != nil {
		log.Fatalf("query: %v", err)
	}

	allow := map[string]bool{}
	for _, part := range strings.Split(*only, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			allow[part] = true
		}
	}

	var candidates []*schema.User
	for _, u := range rows {
		if u == nil || u.Email == "" || u.EmailVerified || u.IsDeleted {
			continue
		}
		// Conservative filter: federation or code registration types are the
		// populations most likely to have a proof trail. Operators still must
		// apply README criteria (OTP prove / verified IdP / manual attestation)
		// before -dry-run=false — prefer -only after reviewing the dry-run list.
		rt := u.RegisterType
		if rt != "Federation" && rt != "Code" && rt != "" {
			// Keep empty RegisterType (legacy) for operator review via -only.
			if len(allow) == 0 {
				continue
			}
		}
		key := u.Owner + "/" + u.Name
		if len(allow) > 0 && !allow[key] {
			continue
		}
		candidates = append(candidates, u)
	}

	fmt.Printf("candidates=%d dry_run=%v org=%q\n", len(candidates), *dry, *org)
	for _, u := range candidates {
		fmt.Printf("candidate owner=%s name=%s register_type=%s email_domain=%s\n",
			u.Owner, u.Name, u.RegisterType, emailDomain(u.Email))
		if *dry {
			continue
		}
		u.EmailVerified = true
		if err := u.UpdateCtx(ctx); err != nil {
			log.Fatalf("update %s/%s: %v", u.Owner, u.Name, err)
		}
		fmt.Printf("updated owner=%s name=%s\n", u.Owner, u.Name)
	}
}

func emailDomain(email string) string {
	_, dom, ok := strings.Cut(strings.ToLower(email), "@")
	if !ok {
		return ""
	}
	return dom
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

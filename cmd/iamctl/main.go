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

// Command iamctl is the operational CLI for Hanzo IAM.
//
// Subcommands are designed to run as one-shot Kubernetes Jobs that
// reconcile IAM state from KMS-sourced configuration. Each subcommand
// is idempotent and safe to re-run.
//
// Subcommands:
//
//	init-providers      Upsert OAuth provider rows (GitHub, Google, …)
//	                    from environment variables sourced from KMS.
//	wire-providers      Attach the GitHub + Google providers to every
//	                    real-org application (idempotent).
//	clean-spam-orgs     Identify and (with --apply) delete suspicious
//	                    organizations. DRY-RUN by default.
//
// Authentication. iamctl talks to IAM's HTTP API at IAM_ENDPOINT using
// the Casdoor-style clientId+clientSecret query-parameter scheme. Both
// credentials are read from env vars IAM_CLIENT_ID and IAM_CLIENT_SECRET
// (these are the admin client's credentials, sourced from KMS at deploy
// time via KMSSecret).
//
// Usage examples (inside a Job):
//
//	iamctl init-providers
//	iamctl wire-providers
//	iamctl clean-spam-orgs                  # dry-run, prints plan
//	iamctl clean-spam-orgs --apply          # actually deletes
//
// Exit codes:
//
//	0  success (idempotent — also returned on no-op runs)
//	1  configuration / env-var error
//	2  IAM API error
package main

import (
	"fmt"
	"os"
)

const usageText = `iamctl — operational CLI for Hanzo IAM

USAGE
    iamctl <subcommand> [flags]

SUBCOMMANDS
    init-providers      Upsert OAuth provider rows from KMS-sourced env.
                        Reads GITHUB_CLIENT_ID/SECRET and GOOGLE_CLIENT_ID/SECRET
                        and upserts provider rows owned by admin org.

    wire-providers      Attach provider-github + provider-google to every
                        application in every real org (excluding admin).
                        Idempotent — re-runs are no-ops once converged.

    clean-spam-orgs     Identify suspicious organizations created by spam
                        signups (numeric-suffix names, reserved-word
                        collisions, fresh orgs with zero users). DRY-RUN
                        by default; pass --apply to actually delete.

ENVIRONMENT
    IAM_ENDPOINT        Base URL of the IAM API (default: http://localhost:8000)
    IAM_CLIENT_ID       Admin app client id (required; KMS-sourced)
    IAM_CLIENT_SECRET   Admin app client secret (required; KMS-sourced)
    IAM_ADMIN_ORG       Admin org name (default: admin)

EXAMPLES
    # In an init-job that runs once per IAM deploy:
    iamctl init-providers && iamctl wire-providers

    # Periodic cleanup CronJob (dry-run, alerts on findings):
    iamctl clean-spam-orgs

    # One-shot cleanup with apply:
    iamctl clean-spam-orgs --apply

EXIT CODES
    0  success
    1  configuration / env-var error
    2  IAM API error
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "init-providers":
		os.Exit(runInitProviders(args))
	case "wire-providers":
		os.Exit(runWireProviders(args))
	case "clean-spam-orgs":
		os.Exit(runCleanSpamOrgs(args))
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usageText)
	default:
		fmt.Fprintf(os.Stderr, "iamctl: unknown subcommand %q\n\n", sub)
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}
}

var version = "(dev)" // set by linker -X main.version=...

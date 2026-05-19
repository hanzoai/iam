// Command iam is the administrative CLI for Hanzo IAM.
//
// Usage:
//
//	iam status                              Check IAM server health
//	iam version                             Print version and exit
//	iam app list [--owner=<slug>] [--json]  List applications
//	iam app get <client-id> [--json]        Get one application by client ID
//	iam app upsert <file.json>              Idempotent upsert from JSON
//	iam app delete <client-id>              Delete an application
//	iam app redirect add <id> <url>...      Add redirect URIs (idempotent)
//	iam app redirect list <id> [--json]     List redirect URIs
//	iam app redirect remove <id> <url>      Remove a redirect URI
//	iam user list [--owner=<slug>] [--json] List users
//	iam user get <owner> <name> [--json]    Get one user
//	iam user create <file.json>             Create a user
//	iam org list [--json]                   List organizations
//	iam org create <file.json>              Create an organization
//	iam org delete <name>                   Delete an organization
//
// See docs/CLI.md for the full reference.
package main

import (
	"fmt"
	"os"

	"github.com/hanzoai/iam/cmd/iam/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

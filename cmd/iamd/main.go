// Command iamd is the IAM server daemon.
//
// Usage:
//
//	iamd serve     Start the IAM server (default)
//	iamd version   Print version and exit
package main

import (
	"fmt"
	"os"

	"github.com/hanzoai/iam/cmd/iam/cli"
	"github.com/hanzoai/iam/iamserver"
)

var version = "(dev)"

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "serve":
		// Convergent provisioning: when IAM_PROVISION_ON_BOOT is set, reconcile
		// the per-brand desktop OAuth apps + social/email/sms providers against
		// our own API as soon as it is serving. Idempotent and self-healing —
		// every deploy re-converges with zero out-of-band kubectl/Jobs. Runs in
		// the background so it cannot delay or block the server starting.
		if cli.ProvisionOnBootEnabled() {
			go func() {
				if err := cli.ProvisionOnBoot(true); err != nil {
					fmt.Fprintf(os.Stderr, "iamd: provision-on-boot: %v\n", err)
				}
			}()
		}
		iamserver.Run()
	case "version":
		fmt.Printf("iamd %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "Usage: iamd <serve|version>\n")
		os.Exit(1)
	}
}

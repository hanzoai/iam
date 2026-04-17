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
		iamserver.Run()
	case "version":
		fmt.Printf("iamd %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "Usage: iamd <serve|version>\n")
		os.Exit(1)
	}
}

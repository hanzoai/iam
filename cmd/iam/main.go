// Command iam is the administrative CLI for IAM.
//
// Usage:
//
//	iam status     Check IAM server health
//	iam token      Generate or validate a JWT
//	iam seed       Seed init_data into the database
//	iam version    Print version and exit
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var version = "(dev)"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "status":
		cmdStatus()
	case "version":
		fmt.Printf("iam %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "iam: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func cmdStatus() {
	addr := envOr("IAM_ADDR", "http://localhost:8000")
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(addr + "/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "iam: health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("status: %d\n%s\n", resp.StatusCode, body)
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: iam <command> [flags]

Commands:
  status     Check IAM server health
  version    Print version

Global Flags:
  IAM_ADDR   IAM server address (default: http://localhost:8000)`)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

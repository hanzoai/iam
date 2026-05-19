// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

// newStatusCmd preserves the original `iam status` behaviour: hit the
// /healthz endpoint, print the HTTP status code + raw body. No bearer
// token required — healthz is intentionally unauthenticated so probes
// (k8s, smoke checks) can hit it without secrets.
func newStatusCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check IAM server health",
		Long: `Check IAM server health by issuing GET /healthz.

Prints "status: <code>" on the first line followed by the raw response
body. No authentication required.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := cfg.resolve()
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(c.Addr + "/healthz")
			if err != nil {
				return fmt.Errorf("iam: health check failed: %w", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("status: %d\n%s\n", resp.StatusCode, body)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fmt.Errorf("iam: health check returned %d", resp.StatusCode)
			}
			return nil
		},
	}
}

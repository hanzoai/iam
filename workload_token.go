// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"github.com/hanzoai/iam/pkg/workload"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// secret is the shared workload-file ABI used by cloud's credential init. The
// assertion stays with that init; the build sees only an admitted reader JWT.
func workloadCredentialCmd() *cobra.Command {
	root := &cobra.Command{Use: "secret", Short: "Deliver a native workload credential"}
	var out, reader string
	token := &cobra.Command{Use: "token", Short: "Write an expiring native IAM workload token to tmpfs", RunE: func(cmd *cobra.Command, _ []string) error {
		if out == "" {
			return fmt.Errorf("--out is required")
		}
		t, err := workload.Pod(cmd.Context())
		if err != nil {
			return err
		}
		if !strings.HasPrefix(t.AccessToken, "ey") || strings.Count(t.AccessToken, ".") != 2 || time.Until(t.Expiry) < 30*time.Minute {
			return fmt.Errorf("IAM issued no JWT valid for the build window")
		}
		if reader != "" {
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, strings.TrimRight(reader, "/")+"/v1/identity-authority", nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+t.AccessToken)
			res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
			if err != nil {
				return fmt.Errorf("native reader admission unreachable")
			}
			defer res.Body.Close()
			var role struct {
				Authority string `json:"authority"`
				Issuer    string `json:"issuer"`
				Role      string `json:"credentialRole"`
			}
			if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&role) != nil || role.Authority != "hanzo-iam" || role.Issuer != "https://hanzo.id" || role.Role != "reader" {
				return fmt.Errorf("Forge did not admit a native IAM reader")
			}
		}
		if err = os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			return err
		}
		f, err := os.CreateTemp(filepath.Dir(out), ".iam-token-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if _, err = f.WriteString(t.AccessToken); err != nil {
			f.Close()
			return err
		}
		if err = f.Chmod(0400); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		return os.Rename(f.Name(), out)
	}}
	token.Flags().StringVar(&out, "out", "", "token file on a memory-backed volume")
	token.Flags().StringVar(&reader, "forge-reader", "", "native Forge origin that must admit the reader")
	root.AddCommand(token)
	return root
}

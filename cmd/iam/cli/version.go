// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newVersionCmd preserves the original `iam version` behaviour: print
// "iam <version>" on stdout. Version is link-time injected.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("iam %s\n", Version)
		},
	}
}

// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import "testing"

// TestInitAppsCmd_Shape verifies the command wires up. The reconcile mechanism
// (conventions, config parsing, idempotency) is brand-neutral and tested in the
// provision package; this only guards the cobra surface.
func TestInitAppsCmd_Shape(t *testing.T) {
	cmd := newInitAppsCmd()
	if cmd.Use != "init-apps" {
		t.Fatalf("Use = %q, want init-apps", cmd.Use)
	}
	if cmd.RunE == nil {
		t.Fatal("init-apps must have a RunE")
	}
	if f := cmd.Flags().Lookup("verbose"); f == nil {
		t.Fatal("init-apps must expose --verbose")
	}
}

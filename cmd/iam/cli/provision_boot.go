// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// bootProvisionRetries / bootProvisionInterval bound how long boot-time
// provisioning waits for the local IAM API (started in the same process) to
// begin serving. The reconcilers list orgs/apps first, so a not-yet-ready
// server surfaces as a transient error we retry through.
const (
	bootProvisionRetries  = 30
	bootProvisionInterval = 2 * time.Second
)

// ProvisionOnBootEnabled reports whether the iamd server should self-reconcile
// brand apps + providers on startup. Off by default; opt in with
// IAM_PROVISION_ON_BOOT=1|true|yes on the Deployment.
func ProvisionOnBootEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("IAM_PROVISION_ON_BOOT"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ProvisionOnBoot runs the idempotent provisioning reconcilers
// (init-apps -> init-providers -> wire-providers) against the local IAM API.
//
// It is the convergent, self-healing counterpart to the one-shot provisioning
// Jobs: iamd calls it on startup so every deploy re-reconciles the per-brand
// desktop OAuth apps (hanzo/zoo/lux) and the social/email/sms providers with
// ZERO out-of-band kubectl. Idempotent — existing rows are left untouched.
//
// init-apps is required (without the brand apps, get-app-login returns
// "Invalid client_id" and wire-providers has nothing to attach to). The
// provider steps are best-effort: when their optional secrets are not yet
// KMS-synced, init-providers/wire-providers are logged and skipped rather than
// failing the boot.
func ProvisionOnBoot(verbose bool) error {
	cfg, err := loadProvEnv()
	if err != nil {
		return fmt.Errorf("provision-on-boot: %w", err)
	}
	client := newProvClient(cfg)

	// Retry init-apps until the in-process server is serving (idempotent).
	var lastErr error
	for attempt := 1; attempt <= bootProvisionRetries; attempt++ {
		if lastErr = runInitApps(client, cfg, verbose); lastErr == nil {
			break
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "provision-on-boot: init-apps not ready (attempt %d/%d): %v\n",
				attempt, bootProvisionRetries, lastErr)
		}
		time.Sleep(bootProvisionInterval)
	}
	if lastErr != nil {
		return fmt.Errorf("provision-on-boot: init-apps: %w", lastErr)
	}

	// Providers are best-effort — their credentials are optional / may land later.
	if err := runInitProviders(client, cfg, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "provision-on-boot: init-providers (non-fatal): %v\n", err)
	}
	if err := runWireProviders(client, cfg, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "provision-on-boot: wire-providers (non-fatal): %v\n", err)
	}
	return nil
}

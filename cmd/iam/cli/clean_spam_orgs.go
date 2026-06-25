// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// suspiciousReason explains why an org is flagged. Logged so future spam
// patterns can be tuned by reviewing the historical reasons.
type suspiciousReason string

const (
	reasonNumericSuffix suspiciousReason = "numeric-suffix" // e.g. "hanzo42", "myorg123"
	reasonReservedWord  suspiciousReason = "reserved-word"  // e.g. "hanzowoo", "my-hanzo"
	reasonFreshNoUsers  suspiciousReason = "fresh-no-users" // age <24h AND zero users
)

// numericSuffixRE matches names ending in one or more digits — a strong spam
// signal because legitimate orgs are named after companies/projects.
var numericSuffixRE = regexp.MustCompile(`\d+$`)

// reservedWordCollisions are names clearly meant to impersonate or spam the
// canonical org. Lower-case match.
var reservedWordCollisions = map[string]bool{
	"hanzowoo":   true,
	"my-hanzo":   true,
	"hanzo-new":  true,
	"superuser":  true,
	"admin-new":  true,
	"hanzo-test": true,
}

// orgWithMeta is the subset of org data we need to evaluate spam heuristics.
type orgWithMeta struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	CreatedTime string `json:"createdTime"`
}

// userOfOrg is the minimal user shape — we only need the count.
type userOfOrg struct {
	Name string `json:"name"`
}

// spamFinding is one row of the plan/result table — an org plus the reasons it
// was flagged.
type spamFinding struct {
	Org     orgWithMeta
	Reasons []suspiciousReason
}

// newCleanSpamOrgsCmd builds `iam clean-spam-orgs`.
func newCleanSpamOrgsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clean-spam-orgs",
		Short: "Identify (and with --apply delete) spam organizations",
		Long: `Identify suspicious organizations created by spam signups
(numeric-suffix names, reserved-word collisions, fresh orgs with zero users).
DRY-RUN by default — prints the plan and exits 0. Pass --apply to actually
delete.

Protected orgs are NEVER deleted regardless of heuristics: the admin org and
the canonical brand orgs (hanzo, lux, zoo, pars, adnexus, bootnode).

Environment is the same admin-app credential set as the other provisioning
commands (IAM_ENDPOINT, IAM_CLIENT_ID, IAM_CLIENT_SECRET, IAM_ADMIN_ORG).`,
		Args: cobra.NoArgs,
	}
	verbose := newProvisionVerboseFlag(cmd)
	apply := cmd.Flags().Bool("apply", false, "actually delete (default: dry-run)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadProvEnv()
		if err != nil {
			return fmt.Errorf("clean-spam-orgs: %w", err)
		}
		client := newProvClient(cfg)
		return runCleanSpamOrgs(client, cfg, *apply, *verbose)
	}
	return cmd
}

// runCleanSpamOrgs lists matched orgs and prints a plan; with apply=true it
// deletes each matched org. Idempotent: re-running after a successful apply is
// a no-op.
func runCleanSpamOrgs(client *provClient, cfg *provConfig, apply, verbose bool) error {
	orgs, err := listOrgsFull(client, cfg.AdminOrg)
	if err != nil {
		return fmt.Errorf("clean-spam-orgs: list orgs: %w", err)
	}

	protected := protectedOrgs(cfg.AdminOrg)
	var plan []spamFinding

	for _, o := range orgs {
		if protected[o.Name] {
			if verbose {
				fmt.Printf("[skip] %s — protected\n", o.Name)
			}
			continue
		}
		reasons := evaluate(client, cfg.AdminOrg, o)
		if len(reasons) == 0 {
			continue
		}
		plan = append(plan, spamFinding{Org: o, Reasons: reasons})
	}

	if len(plan) == 0 {
		fmt.Println("clean-spam-orgs: no suspicious orgs found")
		return nil
	}

	fmt.Printf("clean-spam-orgs: %d candidates\n", len(plan))
	for _, p := range plan {
		fmt.Printf("  %-32s  reasons=%v  created=%s\n", p.Org.Name, p.Reasons, p.Org.CreatedTime)
	}

	if !apply {
		fmt.Println("\n(dry-run; pass --apply to delete)")
		return nil
	}

	failed := 0
	for _, p := range plan {
		if err := deleteOrg(client, cfg.AdminOrg, p.Org.Name); err != nil {
			fmt.Printf("[fail] %s: %v\n", p.Org.Name, err)
			failed++
			continue
		}
		auditDeletion(p)
		fmt.Printf("[del ] %s\n", p.Org.Name)
	}
	if failed > 0 {
		return fmt.Errorf("clean-spam-orgs: %d delete(s) failed", failed)
	}
	return nil
}

func protectedOrgs(adminOrg string) map[string]bool {
	// The admin org always wins; brand orgs are protected by name. Listed
	// explicitly so a typo can't tank a real org.
	return map[string]bool{
		adminOrg:   true,
		"hanzo":    true,
		"lux":      true,
		"zoo":      true,
		"pars":     true,
		"adnexus":  true,
		"bootnode": true,
	}
}

// evaluate returns the set of suspicious reasons matched by org o. Returns nil
// if no rule fires. Deterministic given (o, current_time, user_count).
func evaluate(c *provClient, adminOrg string, o orgWithMeta) []suspiciousReason {
	var reasons []suspiciousReason
	lname := strings.ToLower(o.Name)

	if numericSuffixRE.MatchString(o.Name) {
		reasons = append(reasons, reasonNumericSuffix)
	}
	if reservedWordCollisions[lname] {
		reasons = append(reasons, reasonReservedWord)
	}
	if isFreshAndEmpty(c, adminOrg, o) {
		reasons = append(reasons, reasonFreshNoUsers)
	}
	return reasons
}

// isFreshAndEmpty returns true when the org's CreatedTime is younger than 24h
// AND the org has zero users. Either signal alone is weak; together they are a
// strong spam signal (typical scripted signup pattern).
func isFreshAndEmpty(c *provClient, adminOrg string, o orgWithMeta) bool {
	t, err := parseIAMTime(o.CreatedTime)
	if err != nil {
		return false
	}
	if time.Since(t) > 24*time.Hour {
		return false
	}
	count, err := userCount(c, adminOrg, o.Name)
	if err != nil {
		return false
	}
	return count == 0
}

func parseIAMTime(s string) (time.Time, error) {
	// IAM stores ISO-8601; tolerate both with and without Z.
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable createdTime %q", s)
}

func userCount(c *provClient, adminOrg, org string) (int, error) {
	q := url.Values{}
	q.Set("owner", org) // users are owned by their org, not the admin org
	var users []userOfOrg
	if err := c.get("/v1/iam/get-users", q, &users); err != nil {
		return 0, err
	}
	return len(users), nil
}

func listOrgsFull(c *provClient, adminOrg string) ([]orgWithMeta, error) {
	q := url.Values{}
	q.Set("owner", adminOrg)
	var rows []orgWithMeta
	if err := c.get("/v1/iam/get-organizations", q, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func deleteOrg(c *provClient, adminOrg, name string) error {
	q := url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", adminOrg, name))
	body := map[string]string{"owner": adminOrg, "name": name}
	var ok string
	return c.postJSON("/v1/iam/delete-organization", q, body, &ok)
}

// auditDeletion writes a structured record to stdout. The Job's logs land in
// the cluster log pipeline, which is the cheapest reliable audit path.
func auditDeletion(p spamFinding) {
	rec := map[string]any{
		"event":   "iam.clean-spam-orgs.deleted",
		"org":     p.Org.Name,
		"reasons": p.Reasons,
		"created": p.Org.CreatedTime,
		"at":      time.Now().UTC().Format(time.RFC3339),
	}
	buf, _ := json.Marshal(rec)
	fmt.Println(string(buf))
}

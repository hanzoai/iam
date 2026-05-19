// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// suspiciousReason explains why an org is flagged. Persisted to the
// audit-log payload for KMS so future spam patterns can be tuned by
// reviewing the historical reasons.
type suspiciousReason string

const (
	reasonNumericSuffix suspiciousReason = "numeric-suffix" // e.g. "hanzo42", "myorg123"
	reasonReservedWord  suspiciousReason = "reserved-word"  // e.g. "hanzowoo", "my-hanzo"
	reasonFreshNoUsers  suspiciousReason = "fresh-no-users" // age <24h AND zero users
)

// numericSuffixRE matches names ending in one or more digits — a strong
// spam signal because legitimate orgs are named after companies/projects.
var numericSuffixRE = regexp.MustCompile(`\d+$`)

// reservedWordCollisions are names that are clearly meant to impersonate
// or spam the canonical org. Lower-case match.
var reservedWordCollisions = map[string]bool{
	"hanzowoo":   true,
	"my-hanzo":   true,
	"hanzo-new":  true,
	"superuser":  true,
	"admin-new":  true,
	"hanzo-test": true,
}

// orgWithMeta is the subset of org+user data we need to evaluate spam
// heuristics. CreatedTime is IAM's ISO-8601 string field.
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

// runCleanSpamOrgs is the entry point for `iamctl clean-spam-orgs`.
//
// DRY-RUN behavior: lists everything matched and prints a plan; exits 0.
// --apply: actually deletes each matched org via /v1/iam/delete-organization.
//
// Protected orgs are NEVER deleted regardless of heuristics:
//
//   - cfg.AdminOrg (the admin namespace owner — IAM would self-destruct)
//   - any org whose name matches a known brand (hanzo, lux, zoo, pars,
//     adnexus, bootnode) — these are canonical regardless of pattern
func runCleanSpamOrgs(args []string) int {
	fs := flag.NewFlagSet("clean-spam-orgs", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "actually delete (default: dry-run)")
	verbose := fs.Bool("v", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg, err := loadEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iamctl clean-spam-orgs:", err)
		return 1
	}
	client := newClient(cfg)

	orgs, err := listOrgsFull(client, cfg.AdminOrg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iamctl clean-spam-orgs: list orgs:", err)
		return 2
	}

	protected := protectedOrgs(cfg.AdminOrg)
	var plan []spamFinding

	for _, o := range orgs {
		if protected[o.Name] {
			if *verbose {
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
		return 0
	}

	// Print the plan in stable order.
	fmt.Printf("clean-spam-orgs: %d candidates\n", len(plan))
	for _, p := range plan {
		fmt.Printf("  %-32s  reasons=%v  created=%s\n", p.Org.Name, p.Reasons, p.Org.CreatedTime)
	}

	if !*apply {
		fmt.Println("\n(dry-run; pass --apply to delete)")
		return 0
	}

	// Apply path: delete + audit each.
	failed := 0
	for _, p := range plan {
		if err := deleteOrg(client, cfg.AdminOrg, p.Org.Name); err != nil {
			fmt.Fprintf(os.Stderr, "[fail] %s: %v\n", p.Org.Name, err)
			failed++
			continue
		}
		auditDeletion(p)
		fmt.Printf("[del ] %s\n", p.Org.Name)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "clean-spam-orgs: %d delete(s) failed\n", failed)
		return 2
	}
	return 0
}

// spamFinding is one row of the plan/result table — an org plus the
// reasons it was flagged.
type spamFinding struct {
	Org     orgWithMeta
	Reasons []suspiciousReason
}

func protectedOrgs(adminOrg string) map[string]bool {
	// The admin org always wins; brand orgs are protected by name.
	// We list them explicitly here so a typo can't tank a real org.
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

// evaluate returns the set of suspicious reasons matched by org o.
// Returns nil if no rule fires. The reasons are deterministic given
// (o, current_time, user_count).
func evaluate(c *iamClient, adminOrg string, o orgWithMeta) []suspiciousReason {
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

// isFreshAndEmpty returns true when the org's CreatedTime is younger than
// 24h AND the org has zero users. Either signal alone is weak; together
// they are a strong spam signal (typical scripted signup pattern).
func isFreshAndEmpty(c *iamClient, adminOrg string, o orgWithMeta) bool {
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

func userCount(c *iamClient, adminOrg, org string) (int, error) {
	q := url.Values{}
	q.Set("owner", org) // users are owned by their org, not the admin org
	var users []userOfOrg
	if err := c.get("/v1/iam/get-users", q, &users); err != nil {
		return 0, err
	}
	return len(users), nil
}

func listOrgsFull(c *iamClient, adminOrg string) ([]orgWithMeta, error) {
	q := url.Values{}
	q.Set("owner", adminOrg)
	var rows []orgWithMeta
	if err := c.get("/v1/iam/get-organizations", q, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func deleteOrg(c *iamClient, adminOrg, name string) error {
	q := url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", adminOrg, name))
	body := map[string]string{"owner": adminOrg, "name": name}
	var ok string
	return c.postJSON("/v1/iam/delete-organization", q, body, &ok)
}

// auditDeletion writes a structured record to stdout. The Job's logs
// land in the cluster log pipeline, which is the cheapest reliable
// audit path. A future iteration can POST to KMS's audit workspace.
func auditDeletion(p spamFinding) {
	rec := map[string]interface{}{
		"event":   "iamctl.clean-spam-orgs.deleted",
		"org":     p.Org.Name,
		"reasons": p.Reasons,
		"created": p.Org.CreatedTime,
		"at":      time.Now().UTC().Format(time.RFC3339),
	}
	buf, _ := json.Marshal(rec)
	fmt.Println(string(buf))
}

// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build !skipCi

package object

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestForbiddenVocabulary fails the build if any Hanzo-owned Go source file
// uses one of the retired vocabulary tokens. External import paths are
// exempt — the rule only governs names *we* coin in our own code.
//
// Retired tokens and their replacements:
//
//	built-in / BuiltIn         → admin / Admin
//	superuser / Superuser      → admin / Admin
//	System (as an IAM org/app) → Admin
//	Casdoor / casdoor          → IAM / iam (we own the brand)
//	CasbinRule / casbin_       → AuthzRule / authz_
//	casbin (as a noun in code) → authz
//
// The xormadapter import (github.com/hanzoai/xorm-adapter) is allowed —
// that's an external module path our fork still publishes under its
// historical name. The `casbin/casbin/v2` package path is *not* allowed.
func TestForbiddenVocabulary(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	type rule struct {
		name    string
		pattern *regexp.Regexp
	}
	rules := []rule{
		{"built-in (string)", regexp.MustCompile(`"built-in"|"app-built-in"|"cert-built-in"`)},
		{"BuiltIn identifier", regexp.MustCompile(`\b(BuiltIn|builtIn|builtin)(Org|App|User|Cert|Permission|Adapter|Enforcer|Model|Ldap|Provider|Organization|Application)`)},
		{"superuser (string)", regexp.MustCompile(`"superuser"|"app-superuser"|"cert-superuser"|"permission-superuser"`)},
		{"Superuser identifier", regexp.MustCompile(`\b(Superuser|SuperUser)(Org|App|Cert|Permission)`)},
		{"SystemOrg / SystemApp", regexp.MustCompile(`\bSystem(Org|App|User|Cert|Permission)\b`)},
		{"Casdoor brand", regexp.MustCompile(`(?i)casdoor`)},
		{"casbin/v2 import", regexp.MustCompile(`"github\.com/casbin/casbin/v2"`)},
		{"casbin lowercase", regexp.MustCompile(`\bcasbin\b`)},
		{"CasbinRule identifier", regexp.MustCompile(`\bCasbinRule\b`)},
		{"casbin_ table name", regexp.MustCompile(`"casbin_(api|user)_rule"`)},
	}

	// Files allowed to mention these tokens. Each entry is a glob-style
	// path suffix relative to repo root.
	allow := []string{
		"go.sum",      // dependency hashes
		"go.mod",      // workspace dep declarations
		"NOTICE",      // attribution
		"LICENSE",     // license texts
		"swagger.json", "swagger.yml", // generated API docs (fix later)
		"object/vocabulary_test.go",  // this file
		"object/init_data_pruner.go", // legacy data pruner (deletes old rows)
		"util/authz.go",              // alias boundary: type AuthzRule = xormadapter.CasbinRule
		"routers/static_filter.go",   // scrubs upstream CDN URL out of HTML at runtime
	}
	allowed := func(rel string) bool {
		for _, a := range allow {
			if strings.HasSuffix(rel, a) {
				return true
			}
		}
		return false
	}

	var violations []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip vendored / generated / web-asset / worktree trees.
			base := info.Name()
			if base == "vendor" || base == "node_modules" || base == ".git" ||
				base == "web" || base == ".claude" || base == "swagger" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if allowed(rel) {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		// Lines that are *just* an external-module import are a boundary.
		// We don't own those packages, so the brand bleeds in at the
		// import path; the rule applies to identifiers we coin in our
		// own code.
		for _, r := range rules {
			for _, line := range strings.Split(string(data), "\n") {
				if r.pattern.MatchString(line) {
					violations = append(violations,
						rel+": ["+r.name+"] "+strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("forbidden vocabulary found in %d locations:\n%s",
			len(violations), strings.Join(violations, "\n"))
	}
}

// repoRoot walks up from the test working directory until it finds go.mod.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

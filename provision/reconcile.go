// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package provision

import (
	"fmt"
	"log"
)

// IAM is the minimal administrative surface the reconciler needs. Keeping it an
// interface decouples the reconcile logic from transport: the live HTTP Client,
// the server boot path and tests all satisfy it.
type IAM interface {
	// OrgNames returns the names of every organization owned by the admin org.
	OrgNames() ([]string, error)
	// AppNames returns the application row names belonging to org.
	AppNames(org string) ([]string, error)
	// AddOrg creates one organization.
	AddOrg(*OrgPayload) error
	// AddApp creates one application.
	AddApp(*AppPayload) error
}

// Result reports what a reconcile did. Counts make the operation observable in
// logs without re-querying.
type Result struct {
	OrgsCreated int
	AppsCreated int
	AppsPresent int
}

// Reconcile drives IAM toward cfg: it creates any missing org or application
// and leaves everything already present untouched. It is idempotent — running
// it twice on the same config is a no-op the second time. owner is the admin
// organization that owns the created rows (typically "admin").
func Reconcile(api IAM, cfg *Config, owner string, verbose bool) (Result, error) {
	var res Result
	if owner == "" {
		owner = defaultOwner
	}

	orgNames, err := api.OrgNames()
	if err != nil {
		return res, fmt.Errorf("list orgs: %w", err)
	}
	haveOrg := toSet(orgNames)

	for i := range cfg.Orgs {
		org := cfg.Orgs[i]
		if !haveOrg[org.Name] {
			if err := api.AddOrg(buildOrgPayload(owner, org)); err != nil {
				return res, fmt.Errorf("add org %q: %w", org.Name, err)
			}
			haveOrg[org.Name] = true
			res.OrgsCreated++
			logf(verbose, "[org]  created %s", org.Name)
		}

		appNames, err := api.AppNames(org.Name)
		if err != nil {
			return res, fmt.Errorf("list apps for %q: %w", org.Name, err)
		}
		haveApp := toSet(appNames)

		for j := range org.Apps {
			app := org.Apps[j]
			id := ClientID(org.Name, app.App)
			if haveApp[id] {
				res.AppsPresent++
				logf(verbose, "[skip] %s — already present", id)
				continue
			}
			if err := api.AddApp(buildAppPayload(owner, org, app)); err != nil {
				return res, fmt.Errorf("add app %q: %w", id, err)
			}
			haveApp[id] = true
			res.AppsCreated++
			logf(verbose, "[app]  created %s (type=%s)", id, app.Type)
		}
	}
	return res, nil
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, it := range items {
		if it != "" {
			set[it] = true
		}
	}
	return set
}

func logf(verbose bool, format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

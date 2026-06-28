// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package provision is the declarative app/org reconciler for IAM. It is a
// brand-NEUTRAL mechanism: it ships with NO embedded organizations or
// applications. The operator supplies a declarative config (an org/app graph)
// via a mounted file; the reconciler derives every OAuth detail from a small
// set of sane-default conventions and idempotently reconciles it into IAM.
//
// One way: an operator declares WHAT exists (orgs + apps + a per-app type);
// this package decides HOW each is shaped (redirect URIs, grant types, signin
// methods, client_id). Policy is data; this is the mechanism.
package provision

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the declarative provisioning document. Every value is operator
// data — the package embeds none of it. A nil/empty document provisions
// nothing, which is the correct out-of-box default for the OSS server.
//
// Schema (YAML):
//
//	orgs:
//	  - name: <org>                 # client_id prefix; org row name
//	    displayName: <Name>
//	    homepage: <url>
//	    deepLinkScheme: <scheme>    # optional; required only by desktop apps
//	    apps:
//	      - { app: console, type: spa,          hosts: [console.<host>] }
//	      - { app: api,     type: confidential, hosts: [api.<host>] }
//	      - { app: cli,     type: cli }
//	      - { app: app,     type: desktop }
type Config struct {
	Orgs []OrgConfig `yaml:"orgs"`
}

// OrgConfig declares one organization and the applications under it.
type OrgConfig struct {
	Name           string      `yaml:"name"`
	DisplayName    string      `yaml:"displayName"`
	Homepage       string      `yaml:"homepage"`
	DeepLinkScheme string      `yaml:"deepLinkScheme"`
	Apps           []AppConfig `yaml:"apps"`
}

// AppConfig declares one OAuth client. The client_id (and app row name) is
// derived as "<org>-<app>"; Type selects the convention that derives the rest.
// Hosts are the public web hostnames used to derive browser redirect URIs and
// are consulted only for the web-facing types (spa, confidential).
type AppConfig struct {
	App   string   `yaml:"app"`
	Type  AppType  `yaml:"type"`
	Hosts []string `yaml:"hosts"`
}

// LoadConfig reads and parses a provision document from path. A blank path
// returns an empty Config (provision nothing) — the clean OSS default when
// IAM_PROVISION_CONFIG is unset. A non-blank path that is unreadable or
// invalid is a hard error: misconfiguration must surface, not silently skip.
func LoadConfig(path string) (*Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &Config{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provision config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse provision config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid provision config %s: %w", path, err)
	}
	return &cfg, nil
}

// Validate enforces the invariants the conventions depend on: every org has a
// name, every app has a name and a known type, desktop apps have a deep-link
// scheme to build a redirect from, and no two apps collide on a client_id.
func (c *Config) Validate() error {
	seen := map[string]bool{}
	for i := range c.Orgs {
		org := &c.Orgs[i]
		if strings.TrimSpace(org.Name) == "" {
			return fmt.Errorf("org #%d: name is required", i)
		}
		for j := range org.Apps {
			app := &org.Apps[j]
			if strings.TrimSpace(app.App) == "" {
				return fmt.Errorf("org %q app #%d: app is required", org.Name, j)
			}
			if !app.Type.Valid() {
				return fmt.Errorf("org %q app %q: invalid type %q (want one of: %s)",
					org.Name, app.App, app.Type, strings.Join(appTypeNames(), ", "))
			}
			if app.Type == TypeDesktop && strings.TrimSpace(org.DeepLinkScheme) == "" {
				return fmt.Errorf("org %q app %q: type %q requires the org's deepLinkScheme",
					org.Name, app.App, TypeDesktop)
			}
			id := ClientID(org.Name, app.App)
			if seen[id] {
				return fmt.Errorf("duplicate client_id %q", id)
			}
			seen[id] = true
		}
	}
	return nil
}

// ClientID is the one-and-only client_id derivation: "<org>-<app>". It is also
// the application row name, so the two never drift.
func ClientID(org, app string) string {
	return org + "-" + app
}

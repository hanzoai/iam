// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package object

import "github.com/hanzoai/iam/conf"

// Admin-vocabulary constructors. The IAM data model has two slots on every
// row — owner (the org that owns it) and name (the resource). For the
// admin-owned bootstrap records, owner is always conf.AdminOrg and name is
// the specific resource name. These constructors hide the owner/name
// composite so callers stop spelling "admin"/"admin" everywhere.

// NewOrg returns an *Organization placeholder owned by the admin org with
// the given name. Useful for non-admin orgs that the admin user creates.
func NewOrg(name string) *Organization {
	return &Organization{Owner: conf.AdminOrg, Name: name}
}

// NewAdminOrg returns the admin organization placeholder (owner=name=admin).
func NewAdminOrg() *Organization {
	return &Organization{Owner: "admin", Name: conf.AdminOrg}
}

// NewAdminApp returns the IAM application placeholder owned by the admin org.
func NewAdminApp() *Application {
	return &Application{Owner: conf.AdminOrg, Name: conf.AdminApp}
}

// NewAdminUser returns the bootstrap admin user placeholder.
func NewAdminUser() *User {
	return &User{Owner: conf.AdminOrg, Name: conf.AdminUser}
}

// AdminAppOrganization is the value to drop into Application.Organization /
// User.SignupApplication when wiring records to the admin app.
func AdminAppOrganization() string { return conf.AdminOrg }

// AdminCertName is the name of the JWT signing cert for the admin app.
func AdminCertName() string { return "cert-" + conf.AdminApp }

// AdminPermissionName is the name of the admin permission row.
func AdminPermissionName() string { return "permission-" + conf.AdminApp }

// AdminUserModelName / AdminAPIModelName are authz model names.
func AdminUserModelName() string { return "user-model-" + conf.AdminApp }
func AdminAPIModelName() string  { return "api-model-" + conf.AdminApp }

// AdminUserAdapterName / AdminAPIAdapterName are authz adapter names.
func AdminUserAdapterName() string { return "user-adapter-" + conf.AdminApp }
func AdminAPIAdapterName() string  { return "api-adapter-" + conf.AdminApp }

// AdminUserEnforcerName / AdminAPIEnforcerName are authz enforcer names.
func AdminUserEnforcerName() string { return "user-enforcer-" + conf.AdminApp }
func AdminAPIEnforcerName() string  { return "api-enforcer-" + conf.AdminApp }

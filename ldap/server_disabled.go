//go:build !ldapserver

// Copyright 2022 The Hanzo Authors. All Rights Reserved.
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

// Package ldap's LDAP server is GPL-2.0-encumbered: it links the
// github.com/lor00x/goldap/message ASN.1 codec (and github.com/hanzoai/ldapserver,
// which depends on it) with NO linking exception. Static linking would force
// the entire IAM binary — and any product that embeds it, e.g. the fused
// hanzoai/cloud binary — under GPL-2.0, blocking proprietary distribution.
//
// The full server therefore lives behind the `ldapserver` build tag. The
// DEFAULT build (no tag) compiles only this file, which provides a no-op
// StartLdapServer so iamserver can call it unconditionally. The LDAP *client*
// used for directory auto-sync (object/ldap_conn.go) uses the MIT-licensed
// github.com/go-ldap/ldap/v3 and is unaffected — only the inbound LDAP server
// is gated.
//
// To ship the LDAP server, build with: go build -tags ldapserver ./...

package ldap

import "log"

// StartLdapServer is a no-op in the default build. The real LDAP server is
// only compiled when the `ldapserver` build tag is set (see server.go), which
// pulls in the GPL-2.0 goldap dependency. Without the tag, IAM serves no
// inbound LDAP; directory auto-sync (the LDAP client) is unaffected.
func StartLdapServer() {
	log.Print("LDAP server disabled: build with -tags ldapserver to enable (GPL-2.0 dependency)")
}

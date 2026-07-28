// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"reflect"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// GET /v1/iam/linked-accounts — the caller's linked social/OAuth identities.
//
// schema.User has NO single "linkedIdentities" array; a linked identity is stored as
// the connector's own column (User.GitHub, User.Google, …) holding the federated
// subject — the legacy data model. So the linked accounts ARE those per-connector
// columns that are set; this returns [{provider, subject}] for each non-empty one.
// Each item carries only the subject string (the schema stores no per-link display
// name / avatar / linkedAt), so a richer per-link shape is not available from iam.
// Self-scoped: resolved from the caller (callerOf), never the request.

// PathLinkedAccounts is the canonical linked-identities endpoint.
const PathLinkedAccounts = "/v1/iam/linked-accounts"

// connectorTags is the set of User json tags that hold a linked federated-identity
// subject — the legacy per-connector columns (schema/user.go "Linked
// federated-identity subjects"). ONE list; linked-accounts reflects the non-empty
// ones out, so a new connector column is picked up by adding its tag here only.
var connectorTags = fields(
	"github google qq wechat facebook dingtalk weibo gitee linkedin wecom lark gitlab " +
		"adfs baidu alipay iam infoflow apple azuread azureadb2c slack steam bilibili okta " +
		"douyin kwai line amazon auth0 battlenet bitbucket box cloudfoundry dailymotion deezer " +
		"digitalocean discord dropbox eveonline fitbit gitea heroku influxcloud instagram " +
		"intercom kakao lastfm mailru meetup microsoftonline naver nextcloud onedrive oura " +
		"patreon paypal salesforce shopify soundcloud spotify strava stripe telegram tiktok " +
		"tumblr twitch twitter typetalk uber vk wepay xero yahoo yammer yandex zoom " +
		"custom custom2 custom3 custom4 custom5 custom6 custom7 custom8 custom9 custom10")

// linkedAccount is one linked social/OAuth identity.
type linkedAccount struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

// linkedAccountsHandler returns the caller's linked identities.
func linkedAccountsHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "please sign in first")
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		if user == nil {
			return httpx.Err(c, "the user does not exist")
		}
		return httpx.Ok(c, linkedAccountsOf(user))
	}
}

// linkedAccountsOf reflects a user's non-empty connector columns into the linked list.
// Reflection over the ONE connectorTags set avoids a per-field cascade and stays
// faithful to whichever columns hold a subject.
func linkedAccountsOf(u *schema.User) []linkedAccount {
	out := []linkedAccount{}
	v := reflect.ValueOf(*u)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if !connectorTags[tag] {
			continue
		}
		if s := v.Field(i).String(); s != "" {
			out = append(out, linkedAccount{Provider: tag, Subject: s})
		}
	}
	return out
}

// fields turns a space-separated tag list into a set.
func fields(list string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(list) {
		m[f] = true
	}
	return m
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Provider is a federated identity / connector configuration (v1 the legacy surface
// `provider`, v2 kind "providers"). One row configures a third-party endpoint
// an application binds to — OAuth/OIDC and SAML identity providers, captcha,
// SMS and email senders, object storage, payment gateways, and ID-verification
// services — carrying its credentials, endpoints, and dialect flags. Field
// complete against the v1 row so no secret, endpoint, or toggle is lost on
// migration. Identity is the (Owner, Name) pair; the orm string key is
// "owner/name".
//
// UserMapping and HttpHeaders carry orm:"serialize" so the column backends
// (hanzoai/sql, hanzoai/datastore) persist them through their string siblings;
// the default SQLite store round-trips the maps inside the entity JSON blob and
// leaves the siblings empty. DisableSsl is a v1 legacy dual-use flag (for a
// WeChat provider it toggles the QR-code path, for Google it toggles phone
// number sync) superseded by SslMode ("" / "Auto", "Enable", "Disable"); it is
// preserved for exact parity.
type Provider struct {
	orm.Model[Provider]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime" orm:"index" url:"-"`

	DisplayName       string `json:"displayName" url:"-"`
	Category          string `json:"category" url:"-"`
	Type              string `json:"type" url:"-"`
	SubType           string `json:"subType" url:"-"`
	Method            string `json:"method" url:"-"`
	ClientId          string `json:"clientId"`
	ClientSecret      string `json:"clientSecret" url:"-"`
	ClientId2         string `json:"clientId2" url:"-"`
	ClientSecret2     string `json:"clientSecret2" url:"-"`
	Cert              string `json:"cert" url:"-"`
	CustomAuthUrl     string `json:"customAuthUrl" url:"-"`
	CustomTokenUrl    string `json:"customTokenUrl" url:"-"`
	CustomUserInfoUrl string `json:"customUserInfoUrl" url:"-"`
	CustomLogo        string `json:"customLogo" url:"-"`
	Scopes            string `json:"scopes" url:"-"`

	UserMapping  map[string]string `json:"userMapping" orm:"serialize" datastore:"-"`
	UserMapping_ string            `json:"-"`
	HttpHeaders  map[string]string `json:"httpHeaders" orm:"serialize" datastore:"-"`
	HttpHeaders_ string            `json:"-"`

	Host       string `json:"host" url:"-"`
	Port       int    `json:"port" url:"-"`
	DisableSsl bool   `json:"disableSsl" url:"-"`
	SslMode    string `json:"sslMode" url:"-"`
	Title      string `json:"title" url:"-"`
	Content    string `json:"content" url:"-"`
	Receiver   string `json:"receiver" url:"-"`

	RegionId     string `json:"regionId" url:"-"`
	SignName     string `json:"signName" url:"-"`
	TemplateCode string `json:"templateCode" url:"-"`
	AppId        string `json:"appId" url:"-"`

	Endpoint         string `json:"endpoint" url:"-"`
	IntranetEndpoint string `json:"intranetEndpoint" url:"-"`
	Domain           string `json:"domain" url:"-"`
	Bucket           string `json:"bucket" url:"-"`
	PathPrefix       string `json:"pathPrefix" url:"-"`

	Metadata               string `json:"metadata" url:"-"`
	IdP                    string `json:"idP" url:"-"`
	IssuerUrl              string `json:"issuerUrl" url:"-"`
	EnableSignAuthnRequest bool   `json:"enableSignAuthnRequest" url:"-"`
	EmailRegex             string `json:"emailRegex" url:"-"`

	ProviderUrl string `json:"providerUrl" url:"-"`
	EnableProxy bool   `json:"enableProxy" url:"-"`
	EnablePkce  bool   `json:"enablePkce" url:"-"`
}

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
	CreatedTime string `json:"createdTime" orm:"index"`

	DisplayName       string `json:"displayName"`
	Category          string `json:"category"`
	Type              string `json:"type"`
	SubType           string `json:"subType"`
	Method            string `json:"method"`
	ClientId          string `json:"clientId"`
	ClientSecret      string `json:"clientSecret"`
	ClientId2         string `json:"clientId2"`
	ClientSecret2     string `json:"clientSecret2"`
	Cert              string `json:"cert"`
	CustomAuthUrl     string `json:"customAuthUrl"`
	CustomTokenUrl    string `json:"customTokenUrl"`
	CustomUserInfoUrl string `json:"customUserInfoUrl"`
	CustomLogo        string `json:"customLogo"`
	Scopes            string `json:"scopes"`

	UserMapping  map[string]string `json:"userMapping" orm:"serialize" datastore:"-"`
	UserMapping_ string            `json:"-"`
	HttpHeaders  map[string]string `json:"httpHeaders" orm:"serialize" datastore:"-"`
	HttpHeaders_ string            `json:"-"`

	Host       string `json:"host"`
	Port       int    `json:"port"`
	DisableSsl bool   `json:"disableSsl"`
	SslMode    string `json:"sslMode"`
	Title      string `json:"title"`
	Content    string `json:"content"`
	Receiver   string `json:"receiver"`

	RegionId     string `json:"regionId"`
	SignName     string `json:"signName"`
	TemplateCode string `json:"templateCode"`
	AppId        string `json:"appId"`

	Endpoint         string `json:"endpoint"`
	IntranetEndpoint string `json:"intranetEndpoint"`
	Domain           string `json:"domain"`
	Bucket           string `json:"bucket"`
	PathPrefix       string `json:"pathPrefix"`

	Metadata               string `json:"metadata"`
	IdP                    string `json:"idP"`
	IssuerUrl              string `json:"issuerUrl"`
	EnableSignAuthnRequest bool   `json:"enableSignAuthnRequest"`
	EmailRegex             string `json:"emailRegex"`

	ProviderUrl string `json:"providerUrl"`
	EnableProxy bool   `json:"enableProxy"`
	EnablePkce  bool   `json:"enablePkce"`
}

// Copyright 2025 Hanzo AI, Inc.
// Portions Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

package object

import (
	"encoding/gob"
	"fmt"
	"os"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/util"
)

// bootstrapAdminPassword returns the plaintext to seed the admin user with.
// Reads IAM_ADMIN_PASSWORD, falls back to the admin user name. The fallback
// matches the historical default (password = "root") so existing deployments
// don't change behavior; new ones get a one-env-var lever to override.
func bootstrapAdminPassword() string {
	if v := os.Getenv("IAM_ADMIN_PASSWORD"); v != "" {
		return v
	}
	return conf.AdminUser
}

// InitDb is the bootstrap entrypoint: it seeds the admin org, the IAM
// application, the bootstrap admin user, and the authz primitives (model,
// adapter, enforcer, permission). All seeds are idempotent — if a row
// already exists with the canonical (owner, name), the seed is skipped.
func InitDb() {
	existed := initAdminOrganization()
	if !existed {
		initAdminPermission()
		initAdminProvider()
		initAdminApplication()
		initAdminCert()
		// No default LDAP seed — example.com/"123" was dev junk.
		// Deployments configure LDAP via the admin console.
		initAdminUser()
	}

	existed = initAdminAPIModel()
	if !existed {
		initAdminAPIAdapter()
		initAdminAPIEnforcer()
		initAdminUserModel()
		initAdminUserAdapter()
		initAdminUserEnforcer()
	}

	initWebAuthn()
}

func getAdminAccountItems() []*AccountItem {
	return []*AccountItem{
		{Name: "Organization", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "ID", Visible: true, ViewRule: "Public", ModifyRule: "Immutable"},
		{Name: "Name", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Display name", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "First name", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Last name", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Avatar", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "User type", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Password", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Email", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Phone", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Country code", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Country/Region", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Location", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Address", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Addresses", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Affiliation", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Title", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "ID card type", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "ID card", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "ID card info", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Real name", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "ID verification", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Homepage", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Bio", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Tag", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Language", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Gender", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Birthday", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Education", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Balance", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Balance credit", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Balance currency", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Cart", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Transactions", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Score", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Karma", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Ranking", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Signup application", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Register type", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Register source", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Roles", Visible: true, ViewRule: "Public", ModifyRule: "Immutable"},
		{Name: "Permissions", Visible: true, ViewRule: "Public", ModifyRule: "Immutable"},
		{Name: "Groups", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Consents", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "3rd-party logins", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Properties", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Is admin", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Is forbidden", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Is deleted", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Multi-factor authentication", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "MFA items", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "WebAuthn credentials", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Last change password time", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Managed accounts", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Face ID", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "MFA accounts", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Need update password", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "IP whitelist", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
	}
}

func initAdminOrganization() bool {
	org := NewAdminOrg()
	existing, err := getOrganization(org.Owner, org.Name)
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return true
	}

	displayName := org.DisplayName
	if displayName == "" {
		displayName = org.Name
	}
	org = &Organization{
		Owner:              org.Owner,
		Name:               org.Name,
		CreatedTime:        util.GetCurrentTime(),
		DisplayName:        displayName,
		WebsiteUrl:         "",
		Favicon:            "",
		PasswordType:       "bcrypt",
		PasswordOptions:    []string{"AtLeast6"},
		CountryCodes:       []string{"US", "ES", "FR", "DE", "GB", "CN", "JP", "KR", "VN", "ID", "SG", "IN"},
		DefaultAvatar:      "",
		UserTypes:          []string{},
		Tags:               []string{},
		Languages:          []string{"en", "es", "fr", "de", "ja", "zh", "vi", "pt", "tr", "pl", "uk"},
		InitScore:          2000,
		AccountItems:       getAdminAccountItems(),
		EnableSoftDeletion: false,
		IsProfilePublic:    false,
		UseEmailAsUsername: false,
		EnableTour:         true,
	}
	_, err = AddOrganization(org)
	if err != nil {
		panic(err)
	}
	return false
}

func initAdminUser() {
	user := NewAdminUser()
	existing, err := getUser(user.Owner, user.Name)
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	user = &User{
		Owner:             conf.AdminOrg,
		Name:              conf.AdminUser,
		CreatedTime:       util.GetCurrentTime(),
		Id:                util.GenerateId(),
		Type:              "normal-user",
		Password:          bootstrapAdminPassword(),
		DisplayName:       "Admin",
		Avatar:            "",
		Email:             "admin@localhost",
		CountryCode:       "US",
		Address:           []string{},
		Affiliation:       "",
		Tag:               "staff",
		Score:             2000,
		Ranking:           1,
		IsAdmin:           true,
		IsForbidden:       false,
		IsDeleted:         false,
		SignupApplication: conf.AdminApp,
		RegisterType:      "Add User",
		RegisterSource:    conf.AdminOrg + "/" + conf.AdminUser,
		CreatedIp:         "127.0.0.1",
		Properties:        make(map[string]string),
	}
	_, err = AddUser(user, "en")
	if err != nil {
		panic(err)
	}
}

func initAdminApplication() {
	app := NewAdminApp()
	existing, err := getApplication(app.Owner, app.Name)
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	app.CreatedTime = util.GetCurrentTime()
	app.DisplayName = "IAM"
	app.Category = "Default"
	app.Type = "All"
	app.Scopes = []*ScopeItem{}
	app.Organization = AdminAppOrganization()
	app.Cert = AdminCertName()
	app.EnablePassword = true
	app.EnableSignUp = false
	app.Providers = []*ProviderItem{
		{Name: "provider_captcha_default", CanSignUp: false, CanSignIn: false, CanUnlink: false, Prompted: false, SignupGroup: "", Rule: "None", Provider: nil},
	}
	app.SigninMethods = []*SigninMethod{
		{Name: "Password", DisplayName: "Password", Rule: "All"},
		{Name: "Verification code", DisplayName: "Verification code", Rule: "All"},
		{Name: "WebAuthn", DisplayName: "WebAuthn", Rule: "None"},
		{Name: "Face ID", DisplayName: "Face ID", Rule: "None"},
	}
	app.SignupItems = []*SignupItem{
		{Name: "ID", Visible: false, Required: true, Prompted: false, Rule: "Random"},
		{Name: "Username", Visible: true, Required: true, Prompted: false, Rule: "None"},
		{Name: "Display name", Visible: true, Required: true, Prompted: false, Rule: "None"},
		{Name: "Password", Visible: true, Required: true, Prompted: false, Rule: "None"},
		{Name: "Confirm password", Visible: true, Required: true, Prompted: false, Rule: "None"},
		{Name: "Email", Visible: true, Required: true, Prompted: false, Rule: "Normal"},
		{Name: "Phone", Visible: true, Required: true, Prompted: false, Rule: "None"},
		{Name: "Agreement", Visible: true, Required: true, Prompted: false, Rule: "None"},
	}
	app.Tags = []string{}
	app.RedirectUris = []string{}
	app.TokenFormat = "JWT"
	app.TokenFields = []string{}
	app.ExpireInHours = 168
	app.FormOffset = 2
	app.CookieExpireInHours = 720

	if _, err := AddApplication(app); err != nil {
		panic(err)
	}
}

func readTokenFromFile() (string, string) {
	pemPath := "./object/token_jwt_key.pem"
	keyPath := "./object/token_jwt_key.key"
	pem, err := os.ReadFile(pemPath)
	if err != nil {
		return "", ""
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return "", ""
	}
	return string(pem), string(key)
}

func initAdminCert() {
	certPEM, keyPEM := readTokenFromFile()
	if certPEM == "" || keyPEM == "" {
		var err error
		certPEM, keyPEM, err = generateRsaKeys(4096, 256, 20, "Hanzo", "Hanzo")
		if err != nil {
			panic(fmt.Sprintf("failed to generate RSA keys for %s: %v", AdminCertName(), err))
		}
	}

	existing, err := getCert(conf.AdminOrg, AdminCertName())
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	cert := &Cert{
		Owner:           conf.AdminOrg,
		Name:            AdminCertName(),
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     "Admin Cert",
		Scope:           "JWT",
		Type:            "x509",
		CryptoAlgorithm: "RS256",
		BitSize:         4096,
		ExpireInYears:   20,
		Certificate:     certPEM,
		PrivateKey:      keyPEM,
	}
	if _, err := AddCert(cert); err != nil {
		panic(err)
	}
}

func initAdminProvider() {
	providers := []*Provider{
		{Owner: conf.AdminOrg, Name: "provider_captcha_default", CreatedTime: util.GetCurrentTime(), DisplayName: "Captcha Default", Category: "Captcha", Type: "Default"},
		{Owner: conf.AdminOrg, Name: "provider_balance", CreatedTime: util.GetCurrentTime(), DisplayName: "Balance", Category: "Payment", Type: "Balance"},
		{Owner: conf.AdminOrg, Name: "provider_payment_dummy", CreatedTime: util.GetCurrentTime(), DisplayName: "Dummy Payment", Category: "Payment", Type: "Dummy"},
	}

	for _, p := range providers {
		existing, err := GetProvider(util.GetId(conf.AdminOrg, p.Name))
		if err != nil {
			panic(err)
		}
		if existing != nil {
			continue
		}
		if _, err := AddProvider(p); err != nil {
			panic(err)
		}
	}
}

func initWebAuthn() {
	gob.Register(webauthn.SessionData{})
}

func initAdminUserModel() {
	existing, err := GetModel(conf.AdminOrg + "/" + AdminUserModelName())
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	m := &Model{
		Owner:       conf.AdminOrg,
		Name:        AdminUserModelName(),
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "User Model",
		ModelText: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`,
	}
	if _, err := AddModel(m); err != nil {
		panic(err)
	}
}

func initAdminAPIModel() bool {
	existing, err := GetModel(conf.AdminOrg + "/" + AdminAPIModelName())
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return true
	}

	m := &Model{
		Owner:       conf.AdminOrg,
		Name:        AdminAPIModelName(),
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "API Model",
		ModelText: `[request_definition]
r = subOwner, subName, method, urlPath, objOwner, objName

[policy_definition]
p = subOwner, subName, method, urlPath, objOwner, objName

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (r.subOwner == p.subOwner || p.subOwner == "*") && \
    (r.subName == p.subName || p.subName == "*" || r.subName != "anonymous" && p.subName == "!anonymous") && \
    (r.method == p.method || p.method == "*") && \
    (keyMatch2(r.urlPath, p.urlPath) || p.urlPath == "*") && \
    (r.objOwner == p.objOwner || p.objOwner == "*") && \
    (r.objName == p.objName || p.objName == "*") || \
    (r.subOwner == r.objOwner && r.subName == r.objName)`,
	}
	if _, err := AddModel(m); err != nil {
		panic(err)
	}
	return false
}

func initAdminPermission() {
	existing, err := GetPermission(conf.AdminOrg + "/" + AdminPermissionName())
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	p := &Permission{
		Owner:        conf.AdminOrg,
		Name:         AdminPermissionName(),
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "Admin Permission",
		Description:  "Admin Permission",
		Users:        []string{conf.AdminOrg + "/*"},
		Groups:       []string{},
		Roles:        []string{},
		Domains:      []string{},
		Model:        conf.AdminOrg + "/" + AdminUserModelName(),
		Adapter:      "",
		ResourceType: "Application",
		Resources:    []string{conf.AdminApp},
		Actions:      []string{"Read", "Write", "Admin"},
		Effect:       "Allow",
		IsEnabled:    true,
		Submitter:    conf.AdminUser,
		Approver:     conf.AdminUser,
		ApproveTime:  util.GetCurrentTime(),
		State:        "Approved",
	}
	if _, err := AddPermission(p); err != nil {
		panic(err)
	}
}

func initAdminUserAdapter() {
	existing, err := GetAdapter(conf.AdminOrg + "/" + AdminUserAdapterName())
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	a := &Adapter{
		Owner:       conf.AdminOrg,
		Name:        AdminUserAdapterName(),
		CreatedTime: util.GetCurrentTime(),
		Table:       "authz_user_rule",
		UseSameDb:   true,
	}
	if _, err := AddAdapter(a); err != nil {
		panic(err)
	}
}

func initAdminAPIAdapter() {
	existing, err := GetAdapter(conf.AdminOrg + "/" + AdminAPIAdapterName())
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	a := &Adapter{
		Owner:       conf.AdminOrg,
		Name:        AdminAPIAdapterName(),
		CreatedTime: util.GetCurrentTime(),
		Table:       "authz_api_rule",
		UseSameDb:   true,
	}
	if _, err := AddAdapter(a); err != nil {
		panic(err)
	}
}

func initAdminUserEnforcer() {
	existing, err := GetEnforcer(conf.AdminOrg + "/" + AdminUserEnforcerName())
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	e := &Enforcer{
		Owner:       conf.AdminOrg,
		Name:        AdminUserEnforcerName(),
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "User Enforcer",
		Model:       conf.AdminOrg + "/" + AdminUserModelName(),
		Adapter:     conf.AdminOrg + "/" + AdminUserAdapterName(),
	}
	if _, err := AddEnforcer(e); err != nil {
		panic(err)
	}
}

func initAdminAPIEnforcer() {
	existing, err := GetEnforcer(conf.AdminOrg + "/" + AdminAPIEnforcerName())
	if err != nil {
		panic(err)
	}
	if existing != nil {
		return
	}

	e := &Enforcer{
		Owner:       conf.AdminOrg,
		Name:        AdminAPIEnforcerName(),
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "API Enforcer",
		Model:       conf.AdminOrg + "/" + AdminAPIModelName(),
		Adapter:     conf.AdminOrg + "/" + AdminAPIAdapterName(),
	}
	if _, err := AddEnforcer(e); err != nil {
		panic(err)
	}
}

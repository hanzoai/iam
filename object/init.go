// Copyright 2021 The Hanzo Authors. All Rights Reserved.
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

func InitDb() {
	existed := initBuiltInOrganization()
	if !existed {
		initBuiltInPermission()
		initBuiltInProvider()
		initBuiltInApplication()
		initBuiltInCert()
		initBuiltInLdap()
		initBuiltInUser()
	}

	existed = initBuiltInApiModel()
	if !existed {
		initBuiltInApiAdapter()
		initBuiltInApiEnforcer()
		initBuiltInUserModel()
		initBuiltInUserAdapter()
		initBuiltInUserEnforcer()
	}

	initWebAuthn()
}

func getBuiltInAccountItems() []*AccountItem {
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

func initBuiltInOrganization() bool {
	organization, err := getOrganization("admin", "superuser")
	if err != nil {
		panic(err)
	}

	if organization != nil {
		return true
	}

	organization = &Organization{
		Owner:              "admin",
		Name:               "superuser",
		CreatedTime:        util.GetCurrentTime(),
		DisplayName:        "Superuser",
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
		AccountItems:       getBuiltInAccountItems(),
		EnableSoftDeletion: false,
		IsProfilePublic:    false,
		UseEmailAsUsername: false,
		EnableTour:         true,
	}
	_, err = AddOrganization(organization)
	if err != nil {
		panic(err)
	}

	return false
}

func initBuiltInUser() {
	user, err := getUser("superuser", "admin")
	if err != nil {
		panic(err)
	}
	if user != nil {
		return
	}

	user = &User{
		Owner:             "superuser",
		Name:              "admin",
		CreatedTime:       util.GetCurrentTime(),
		Id:                util.GenerateId(),
		Type:              "normal-user",
		Password:          "admin",
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
		SignupApplication: "app-superuser",
		RegisterType:      "Add User",
		RegisterSource:    "superuser/admin",
		CreatedIp:         "127.0.0.1",
		Properties:        make(map[string]string),
	}
	_, err = AddUser(user, "en")
	if err != nil {
		panic(err)
	}
}

func initBuiltInApplication() {
	application, err := getApplication("admin", "app-superuser")
	if err != nil {
		panic(err)
	}

	if application != nil {
		return
	}

	application = &Application{
		Owner:          "admin",
		Name:           "app-superuser",
		CreatedTime:    util.GetCurrentTime(),
		DisplayName:    "IAM",
		Category:       "Default",
		Type:           "All",
		Scopes:         []*ScopeItem{},
		Logo:           "",
		HomepageUrl:    "",
		Organization:   "superuser",
		Cert:           "cert-superuser",
		EnablePassword: true,
		EnableSignUp:   false,
		Providers: []*ProviderItem{
			{Name: "provider_captcha_default", CanSignUp: false, CanSignIn: false, CanUnlink: false, Prompted: false, SignupGroup: "", Rule: "None", Provider: nil},
		},
		SigninMethods: []*SigninMethod{
			{Name: "Password", DisplayName: "Password", Rule: "All"},
			{Name: "Verification code", DisplayName: "Verification code", Rule: "All"},
			{Name: "WebAuthn", DisplayName: "WebAuthn", Rule: "None"},
			{Name: "Face ID", DisplayName: "Face ID", Rule: "None"},
		},
		SignupItems: []*SignupItem{
			{Name: "ID", Visible: false, Required: true, Prompted: false, Rule: "Random"},
			{Name: "Username", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Display name", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Password", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Confirm password", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Email", Visible: true, Required: true, Prompted: false, Rule: "Normal"},
			{Name: "Phone", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Agreement", Visible: true, Required: true, Prompted: false, Rule: "None"},
		},
		Tags:          []string{},
		RedirectUris:  []string{},
		TokenFormat:   "JWT",
		TokenFields:   []string{},
		ExpireInHours: 168,
		FormOffset:    2,

		CookieExpireInHours: 720,
	}
	_, err = AddApplication(application)
	if err != nil {
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

func initBuiltInCert() {
	tokenJwtCertificate, tokenJwtPrivateKey := readTokenFromFile()

	// If no PEM files on disk, generate fresh RSA keys.
	if tokenJwtCertificate == "" || tokenJwtPrivateKey == "" {
		var err error
		tokenJwtCertificate, tokenJwtPrivateKey, err = generateRsaKeys(4096, 256, 20, "Hanzo", "Hanzo")
		if err != nil {
			panic(fmt.Sprintf("failed to generate RSA keys for cert-superuser: %v", err))
		}
	}

	cert, err := getCert("admin", "cert-superuser")
	if err != nil {
		panic(err)
	}

	if cert != nil {
		return
	}

	cert = &Cert{
		Owner:           "admin",
		Name:            "cert-superuser",
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     "Superuser Cert",
		Scope:           "JWT",
		Type:            "x509",
		CryptoAlgorithm: "RS256",
		BitSize:         4096,
		ExpireInYears:   20,
		Certificate:     tokenJwtCertificate,
		PrivateKey:      tokenJwtPrivateKey,
	}
	_, err = AddCert(cert)
	if err != nil {
		panic(err)
	}
}

func initBuiltInLdap() {
	ldap, err := GetLdap("ldap-superuser")
	if err != nil {
		panic(err)
	}

	if ldap != nil {
		return
	}

	ldap = &Ldap{
		Id:         "ldap-superuser",
		Owner:      "superuser",
		ServerName: "Superuser LDAP Server",
		Host:       "example.com",
		Port:       389,
		Username:   "cn=admin,dc=example,dc=com",
		Password:   "123",
		BaseDn:     "ou=People,dc=example,dc=com",
		AutoSync:   0,
		LastSync:   "",
	}
	_, err = AddLdap(ldap)
	if err != nil {
		panic(err)
	}
}

func initBuiltInProvider() {
	providers := []*Provider{
		{
			Owner:       "admin",
			Name:        "provider_captcha_default",
			CreatedTime: util.GetCurrentTime(),
			DisplayName: "Captcha Default",
			Category:    "Captcha",
			Type:        "Default",
		},
		{
			Owner:       "admin",
			Name:        "provider_balance",
			CreatedTime: util.GetCurrentTime(),
			DisplayName: "Balance",
			Category:    "Payment",
			Type:        "Balance",
		},
		{
			Owner:       "admin",
			Name:        "provider_payment_dummy",
			CreatedTime: util.GetCurrentTime(),
			DisplayName: "Dummy Payment",
			Category:    "Payment",
			Type:        "Dummy",
		},
	}

	for _, provider := range providers {
		existingProvider, err := GetProvider(util.GetId("admin", provider.Name))
		if err != nil {
			panic(err)
		}

		if existingProvider != nil {
			continue
		}

		_, err = AddProvider(provider)
		if err != nil {
			panic(err)
		}
	}
}

func initWebAuthn() {
	gob.Register(webauthn.SessionData{})
}

func initBuiltInUserModel() {
	model, err := GetModel("superuser/user-model-superuser")
	if err != nil {
		panic(err)
	}

	if model != nil {
		return
	}

	model = &Model{
		Owner:       "superuser",
		Name:        "user-model-superuser",
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
	_, err = AddModel(model)
	if err != nil {
		panic(err)
	}
}

func initBuiltInApiModel() bool {
	model, err := GetModel("superuser/api-model-superuser")
	if err != nil {
		panic(err)
	}

	if model != nil {
		return true
	}

	modelText := `[request_definition]
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
    (r.subOwner == r.objOwner && r.subName == r.objName)`

	model = &Model{
		Owner:       "superuser",
		Name:        "api-model-superuser",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "API Model",
		ModelText:   modelText,
	}
	_, err = AddModel(model)
	if err != nil {
		panic(err)
	}
	return false
}

func initBuiltInPermission() {
	permission, err := GetPermission("superuser/permission-superuser")
	if err != nil {
		panic(err)
	}
	if permission != nil {
		return
	}

	permission = &Permission{
		Owner:        "superuser",
		Name:         "permission-superuser",
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "Superuser Permission",
		Description:  "Superuser Permission",
		Users:        []string{"superuser/*"},
		Groups:       []string{},
		Roles:        []string{},
		Domains:      []string{},
		Model:        "superuser/user-model-superuser",
		Adapter:      "",
		ResourceType: "Application",
		Resources:    []string{"app-superuser"},
		Actions:      []string{"Read", "Write", "Admin"},
		Effect:       "Allow",
		IsEnabled:    true,
		Submitter:    "admin",
		Approver:     "admin",
		ApproveTime:  util.GetCurrentTime(),
		State:        "Approved",
	}
	_, err = AddPermission(permission)
	if err != nil {
		panic(err)
	}
}

func initBuiltInUserAdapter() {
	adapter, err := GetAdapter("superuser/user-adapter-superuser")
	if err != nil {
		panic(err)
	}

	if adapter != nil {
		return
	}

	adapter = &Adapter{
		Owner:       "superuser",
		Name:        "user-adapter-superuser",
		CreatedTime: util.GetCurrentTime(),
		Table:       "casbin_user_rule",
		UseSameDb:   true,
	}
	_, err = AddAdapter(adapter)
	if err != nil {
		panic(err)
	}
}

func initBuiltInApiAdapter() {
	adapter, err := GetAdapter("superuser/api-adapter-superuser")
	if err != nil {
		panic(err)
	}

	if adapter != nil {
		return
	}

	adapter = &Adapter{
		Owner:       "superuser",
		Name:        "api-adapter-superuser",
		CreatedTime: util.GetCurrentTime(),
		Table:       "casbin_api_rule",
		UseSameDb:   true,
	}
	_, err = AddAdapter(adapter)
	if err != nil {
		panic(err)
	}
}

func initBuiltInUserEnforcer() {
	enforcer, err := GetEnforcer("superuser/user-enforcer-superuser")
	if err != nil {
		panic(err)
	}

	if enforcer != nil {
		return
	}

	enforcer = &Enforcer{
		Owner:       "superuser",
		Name:        "user-enforcer-superuser",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "User Enforcer",
		Model:       "superuser/user-model-superuser",
		Adapter:     "superuser/user-adapter-superuser",
	}

	_, err = AddEnforcer(enforcer)
	if err != nil {
		panic(err)
	}
}

func initBuiltInApiEnforcer() {
	enforcer, err := GetEnforcer("superuser/api-enforcer-superuser")
	if err != nil {
		panic(err)
	}

	if enforcer != nil {
		return
	}

	enforcer = &Enforcer{
		Owner:       "superuser",
		Name:        "api-enforcer-superuser",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "API Enforcer",
		Model:       "superuser/api-model-superuser",
		Adapter:     "superuser/api-adapter-superuser",
	}

	_, err = AddEnforcer(enforcer)
	if err != nil {
		panic(err)
	}
}

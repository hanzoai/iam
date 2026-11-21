// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// AccountItem is one self-service profile field an organization exposes to its
// members, together with the rules that govern who may view or change it.
type AccountItem struct {
	Name       string `json:"name" orm:"varchar(255)"`
	Visible    bool   `json:"visible" orm:"bool"`
	ViewRule   string `json:"viewRule" orm:"varchar(255)"`
	ModifyRule string `json:"modifyRule" orm:"varchar(255)"`
	Regex      string `json:"regex" orm:"varchar(255)"`
	Tab        string `json:"tab" orm:"varchar(255)"`
}

// ThemeData is an organization's default UI theme, inherited by its
// applications unless they override it. It is shared with Application, which
// carries the same shape as its per-app theme override.
type ThemeData struct {
	ThemeType    string `json:"themeType" orm:"varchar(30)"`
	ColorPrimary string `json:"colorPrimary" orm:"varchar(10)"`
	BorderRadius int    `json:"borderRadius" orm:"int"`
	IsCompact    bool   `json:"isCompact" orm:"bool"`
	IsEnabled    bool   `json:"isEnabled" orm:"bool"`
}

// Organization is a tenant boundary: the top-level owner scope every other IAM
// entity is filed under. Its natural key is the (Owner, Name) pair; orm carries
// the surrogate id, audit timestamps, and soft-delete flag on the embedded
// Model, while CreatedTime preserves the v1 display timestamp verbatim.
//
// Every field below is carried over from the v1 record so no authentication or
// tenant-policy data is lost in the migration.
type Organization struct {
	orm.Model[Organization]

	Owner       string `json:"owner" orm:"varchar(100) notnull pk"`
	Name        string `json:"name" orm:"varchar(100) notnull pk"`
	CreatedTime string `json:"createdTime" orm:"varchar(100)"`

	DisplayName            string     `json:"displayName" orm:"varchar(100)"`
	WebsiteUrl             string     `json:"websiteUrl" orm:"varchar(100)"`
	Logo                   string     `json:"logo" orm:"varchar(200)"`
	LogoDark               string     `json:"logoDark" orm:"varchar(200)"`
	Favicon                string     `json:"favicon" orm:"varchar(200)"`
	HasPrivilegeConsent    bool       `json:"hasPrivilegeConsent" orm:"bool"`
	PasswordType           string     `json:"passwordType" orm:"varchar(100)"`
	PasswordSalt           string     `json:"passwordSalt" orm:"varchar(100)"`
	PasswordOptions        []string   `json:"passwordOptions" orm:"mediumtext"`
	PasswordObfuscatorType string     `json:"passwordObfuscatorType" orm:"varchar(100)"`
	PasswordObfuscatorKey  string     `json:"passwordObfuscatorKey" orm:"varchar(100)"`
	PasswordExpireDays     int        `json:"passwordExpireDays" orm:"int"`
	CountryCodes           []string   `json:"countryCodes" orm:"mediumtext"`
	DefaultAvatar          string     `json:"defaultAvatar" orm:"varchar(200)"`
	UsePermanentAvatar     bool       `json:"usePermanentAvatar" orm:"bool"`
	DefaultApplication     string     `json:"defaultApplication" orm:"varchar(100)"`
	UserTypes              []string   `json:"userTypes" orm:"mediumtext"`
	Tags                   []string   `json:"tags" orm:"mediumtext"`
	Languages              []string   `json:"languages" orm:"mediumtext"`
	ThemeData              *ThemeData `json:"themeData" orm:"json"`
	MasterPassword         string     `json:"masterPassword" orm:"varchar(200)"`
	DefaultPassword        string     `json:"defaultPassword" orm:"varchar(200)"`
	MasterVerificationCode string     `json:"masterVerificationCode" orm:"varchar(100)"`
	IpWhitelist            string     `json:"ipWhitelist" orm:"varchar(200)"`
	InitScore              int        `json:"initScore" orm:"int"`
	EnableSoftDeletion     bool       `json:"enableSoftDeletion" orm:"bool"`
	IsProfilePublic        bool       `json:"isProfilePublic" orm:"bool"`
	UseEmailAsUsername     bool       `json:"useEmailAsUsername" orm:"bool"`
	EnableTour             bool       `json:"enableTour" orm:"bool"`
	DisableSignin          bool       `json:"disableSignin" orm:"bool"`
	IpRestriction          string     `json:"ipRestriction" orm:"varchar(255)"`
	NavItems               []string   `json:"navItems" orm:"mediumtext"`
	UserNavItems           []string   `json:"userNavItems" orm:"mediumtext"`
	WidgetItems            []string   `json:"widgetItems" orm:"mediumtext"`

	MfaItems           []*MfaItem     `json:"mfaItems" orm:"mediumtext"`
	MfaRememberInHours int            `json:"mfaRememberInHours" orm:"int"`
	AccountMenu        string         `json:"accountMenu" orm:"varchar(20)"`
	AccountItems       []*AccountItem `json:"accountItems" orm:"mediumtext"`

	// Per-organization signin throttle. Zero means "inherit the application
	// default"; a non-zero value overrides it. Safe bounds are clamped by the
	// resource service before persistence.
	FailedSigninLimit      int `json:"failedSigninLimit" orm:"int"`
	FailedSigninFrozenTime int `json:"failedSigninFrozenTime" orm:"int"`

	DcrPolicy string `json:"dcrPolicy" orm:"varchar(100)"`

	LdapAttributes      []string `json:"ldapAttributes" orm:"mediumtext"`
	KerberosRealm       string   `json:"kerberosRealm" orm:"varchar(200)"`
	KerberosKdcHost     string   `json:"kerberosKdcHost" orm:"varchar(200)"`
	KerberosKeytab      string   `json:"kerberosKeytab" orm:"mediumtext"`
	KerberosServiceName string   `json:"kerberosServiceName" orm:"varchar(100)"`

	// Balance fields are read-only mirrors; authoritative balances live in
	// Commerce (billing.hanzo.ai). Carried for field-complete v1 parity.
	OrgBalance      float64 `json:"orgBalance" orm:"double"`
	UserBalance     float64 `json:"userBalance" orm:"double"`
	BalanceCredit   float64 `json:"balanceCredit" orm:"double"`
	BalanceCurrency string  `json:"balanceCurrency" orm:"varchar(100)"`

	IsPersonal bool `json:"isPersonal" orm:"bool"`

	// Founder is the stable storage id of the identity that provisioned this org
	// (self-service onboarding). It is the resume token that makes provisioning
	// converge on a backend where each write autocommits independently (no
	// transaction rollback): after a partial failure that created the org but did
	// not move the founder in, a retry recognises the org as the founder's own and
	// completes it, instead of refusing it as "already taken". It also fences the
	// org to ONE tenant — a different identity can never complete or join it.
	Founder string `json:"founder,omitempty" orm:"varchar(255)"`
}

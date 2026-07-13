// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import (
	"encoding/json"

	"github.com/hanzoai/orm"
)

// User is an identity principal — the v2 form of the v1 Casdoor `user` row,
// re-expressed on hanzoai/orm. It is the authentication entity: the only
// credential material it persists is PasswordHash (a one-way bcrypt digest,
// json:"-" so it never leaves the process) and the legacy hash metadata used
// to migrate rows minted before the bcrypt cutover. The plaintext password is
// never a field on this struct — it arrives on the create/update request,
// is hashed immediately, and is discarded.
//
// The natural key is (Owner, Name): Owner is the tenant/organization slug,
// Name is unique within it. The embedded orm.Model[User] supplies the storage
// id (the OIDC `sub`), the created/updated timestamps, and the CRUD lifecycle.
type User struct {
	orm.Model[User]

	// Identity / tenancy. (Owner, Name) is the natural key; the OIDC `sub`
	// is the embedded orm.Model id.
	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime"`
	UpdatedTime string `json:"updatedTime"`
	DeletedTime string `json:"deletedTime,omitempty"`

	ExternalId string `json:"externalId,omitempty" orm:"index"`
	Type       string `json:"type,omitempty"`

	// Credential material. PasswordHash is a one-way bcrypt digest and is
	// verify-only — json:"-" keeps it off every response. PasswordType and
	// PasswordSalt describe the digest scheme so rows hashed under the legacy
	// argon2id scheme can still be verified and lazily re-hashed to bcrypt.
	PasswordHash string `json:"-"`
	PasswordType string `json:"passwordType,omitempty"`
	PasswordSalt string `json:"-"`

	// Profile.
	DisplayName     string     `json:"displayName,omitempty"`
	FirstName       string     `json:"firstName,omitempty"`
	LastName        string     `json:"lastName,omitempty"`
	Avatar          string     `json:"avatar,omitempty"`
	AvatarType      string     `json:"avatarType,omitempty"`
	PermanentAvatar string     `json:"permanentAvatar,omitempty"`
	Email           string     `json:"email,omitempty" orm:"index"`
	EmailVerified   bool       `json:"emailVerified,omitempty"`
	Phone           string     `json:"phone,omitempty" orm:"index"`
	CountryCode     string     `json:"countryCode,omitempty"`
	Region          string     `json:"region,omitempty"`
	Location        string     `json:"location,omitempty"`
	Address         []string   `json:"address,omitempty"`
	Addresses       []*Address `json:"addresses,omitempty"`
	Affiliation     string     `json:"affiliation,omitempty"`
	Title           string     `json:"title,omitempty"`
	IdCardType      string     `json:"idCardType,omitempty"`
	IdCard          string     `json:"idCard,omitempty" orm:"index"`
	RealName        string     `json:"realName,omitempty"`
	IsVerified      bool       `json:"isVerified,omitempty"`
	Homepage        string     `json:"homepage,omitempty"`
	Bio             string     `json:"bio,omitempty"`
	Tag             string     `json:"tag,omitempty"`
	Language        string     `json:"language,omitempty"`
	Gender          string     `json:"gender,omitempty"`
	Birthday        string     `json:"birthday,omitempty"`
	Education       string     `json:"education,omitempty"`
	Score           int        `json:"score,omitempty"`
	Karma           int        `json:"karma,omitempty"`
	Ranking         int        `json:"ranking,omitempty"`

	// Balance mirrors v1 for lossless migration but is authoritative in
	// Commerce (billing.hanzo.ai), not here — do not write it from IAM.
	Balance         float64 `json:"balance,omitempty"`
	BalanceCredit   float64 `json:"balanceCredit,omitempty"`
	Currency        string  `json:"currency,omitempty"`
	BalanceCurrency string  `json:"balanceCurrency,omitempty"`

	// State flags.
	IsDefaultAvatar   bool   `json:"isDefaultAvatar,omitempty" orm:"default:false"`
	IsOnline          bool   `json:"isOnline,omitempty" orm:"default:false"`
	IsAdmin           bool   `json:"isAdmin,omitempty" orm:"default:false"`
	IsForbidden       bool   `json:"isForbidden,omitempty" orm:"default:false"`
	IsDeleted         bool   `json:"isDeleted,omitempty" orm:"default:false"`
	SignupApplication string `json:"signupApplication,omitempty"`
	Hash              string `json:"hash,omitempty"`
	PreHash           string `json:"preHash,omitempty"`
	RegisterType      string `json:"registerType,omitempty"`
	RegisterSource    string `json:"registerSource,omitempty"`

	// API credentials. AccessSecret / AccessSecretHash / the OAuth tokens are
	// bearer material; AccessSecretHash and the raw secret never serialize.
	// The handler redacts AccessSecret and the token fields before responding.
	AccessKey            string `json:"accessKey,omitempty"`
	AccessSecret         string `json:"accessSecret,omitempty"`
	AccessSecretHash     string `json:"-"`
	AccessToken          string `json:"accessToken,omitempty"`
	OriginalToken        string `json:"originalToken,omitempty"`
	OriginalRefreshToken string `json:"originalRefreshToken,omitempty"`

	// Sign-in provenance.
	CreatedIp      string `json:"createdIp,omitempty"`
	LastSigninTime string `json:"lastSigninTime,omitempty"`
	LastSigninIp   string `json:"lastSigninIp,omitempty"`

	// Linked federated-identity subjects, one column per connector (v1 parity).
	GitHub          string `json:"github,omitempty"`
	Google          string `json:"google,omitempty"`
	QQ              string `json:"qq,omitempty"`
	WeChat          string `json:"wechat,omitempty"`
	Facebook        string `json:"facebook,omitempty"`
	DingTalk        string `json:"dingtalk,omitempty"`
	Weibo           string `json:"weibo,omitempty"`
	Gitee           string `json:"gitee,omitempty"`
	LinkedIn        string `json:"linkedin,omitempty"`
	Wecom           string `json:"wecom,omitempty"`
	Lark            string `json:"lark,omitempty"`
	Gitlab          string `json:"gitlab,omitempty"`
	Adfs            string `json:"adfs,omitempty"`
	Baidu           string `json:"baidu,omitempty"`
	Alipay          string `json:"alipay,omitempty"`
	Iam             string `json:"iam,omitempty"`
	Infoflow        string `json:"infoflow,omitempty"`
	Apple           string `json:"apple,omitempty"`
	AzureAD         string `json:"azuread,omitempty"`
	AzureADB2c      string `json:"azureadb2c,omitempty"`
	Slack           string `json:"slack,omitempty"`
	Steam           string `json:"steam,omitempty"`
	Bilibili        string `json:"bilibili,omitempty"`
	Okta            string `json:"okta,omitempty"`
	Douyin          string `json:"douyin,omitempty"`
	Kwai            string `json:"kwai,omitempty"`
	Line            string `json:"line,omitempty"`
	Amazon          string `json:"amazon,omitempty"`
	Auth0           string `json:"auth0,omitempty"`
	BattleNet       string `json:"battlenet,omitempty"`
	Bitbucket       string `json:"bitbucket,omitempty"`
	Box             string `json:"box,omitempty"`
	CloudFoundry    string `json:"cloudfoundry,omitempty"`
	Dailymotion     string `json:"dailymotion,omitempty"`
	Deezer          string `json:"deezer,omitempty"`
	DigitalOcean    string `json:"digitalocean,omitempty"`
	Discord         string `json:"discord,omitempty"`
	Dropbox         string `json:"dropbox,omitempty"`
	EveOnline       string `json:"eveonline,omitempty"`
	Fitbit          string `json:"fitbit,omitempty"`
	Gitea           string `json:"gitea,omitempty"`
	Heroku          string `json:"heroku,omitempty"`
	InfluxCloud     string `json:"influxcloud,omitempty"`
	Instagram       string `json:"instagram,omitempty"`
	Intercom        string `json:"intercom,omitempty"`
	Kakao           string `json:"kakao,omitempty"`
	Lastfm          string `json:"lastfm,omitempty"`
	Mailru          string `json:"mailru,omitempty"`
	Meetup          string `json:"meetup,omitempty"`
	MicrosoftOnline string `json:"microsoftonline,omitempty"`
	Naver           string `json:"naver,omitempty"`
	Nextcloud       string `json:"nextcloud,omitempty"`
	OneDrive        string `json:"onedrive,omitempty"`
	Oura            string `json:"oura,omitempty"`
	Patreon         string `json:"patreon,omitempty"`
	Paypal          string `json:"paypal,omitempty"`
	SalesForce      string `json:"salesforce,omitempty"`
	Shopify         string `json:"shopify,omitempty"`
	Soundcloud      string `json:"soundcloud,omitempty"`
	Spotify         string `json:"spotify,omitempty"`
	Strava          string `json:"strava,omitempty"`
	Stripe          string `json:"stripe,omitempty"`
	Telegram        string `json:"telegram,omitempty"`
	TikTok          string `json:"tiktok,omitempty"`
	Tumblr          string `json:"tumblr,omitempty"`
	Twitch          string `json:"twitch,omitempty"`
	Twitter         string `json:"twitter,omitempty"`
	Typetalk        string `json:"typetalk,omitempty"`
	Uber            string `json:"uber,omitempty"`
	VK              string `json:"vk,omitempty"`
	Wepay           string `json:"wepay,omitempty"`
	Xero            string `json:"xero,omitempty"`
	Yahoo           string `json:"yahoo,omitempty"`
	Yammer          string `json:"yammer,omitempty"`
	Yandex          string `json:"yandex,omitempty"`
	Zoom            string `json:"zoom,omitempty"`
	Custom          string `json:"custom,omitempty"`
	Custom2         string `json:"custom2,omitempty"`
	Custom3         string `json:"custom3,omitempty"`
	Custom4         string `json:"custom4,omitempty"`
	Custom5         string `json:"custom5,omitempty"`
	Custom6         string `json:"custom6,omitempty"`
	Custom7         string `json:"custom7,omitempty"`
	Custom8         string `json:"custom8,omitempty"`
	Custom9         string `json:"custom9,omitempty"`
	Custom10        string `json:"custom10,omitempty"`

	// Multi-factor authentication. TotpSecret and RecoveryCodes are secret
	// verify-only material — the handler strips them from every response.
	// WebauthnCredentials is carried as raw JSON here for lossless migration;
	// the typed passkey model is the sibling WebauthnCredential entity.
	WebauthnCredentials []json.RawMessage `json:"webauthnCredentials,omitempty"`
	PreferredMfaType    string            `json:"preferredMfaType,omitempty"`
	RecoveryCodes       []string          `json:"recoveryCodes,omitempty"`
	TotpSecret          string            `json:"totpSecret,omitempty"`
	VerificationCode    string            `json:"verificationCode,omitempty"`
	MfaPhoneEnabled     bool              `json:"mfaPhoneEnabled,omitempty"`
	MfaEmailEnabled     bool              `json:"mfaEmailEnabled,omitempty"`
	MfaRadiusEnabled    bool              `json:"mfaRadiusEnabled,omitempty"`
	MfaRadiusUsername   string            `json:"mfaRadiusUsername,omitempty"`
	MfaRadiusProvider   string            `json:"mfaRadiusProvider,omitempty"`
	MfaPushEnabled      bool              `json:"mfaPushEnabled,omitempty"`
	MfaPushReceiver     string            `json:"mfaPushReceiver,omitempty"`
	MfaPushProvider     string            `json:"mfaPushProvider,omitempty"`
	MultiFactorAuths    []*MfaProps       `json:"multiFactorAuths,omitempty"`
	Invitation          string            `json:"invitation,omitempty" orm:"index"`
	InvitationCode      string            `json:"invitationCode,omitempty" orm:"index"`
	FaceIds             []*FaceId         `json:"faceIds,omitempty"`
	Cart                []CartItem        `json:"cart,omitempty"`

	Ldap       string            `json:"ldap,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`

	// Authorization attachments. Roles and Permissions are computed on read
	// from the authz store and carried here for API parity with v1.
	Roles       []*Role       `json:"roles,omitempty"`
	Permissions []*Permission `json:"permissions,omitempty"`
	Groups      []string      `json:"groups,omitempty"`

	LastChangePasswordTime string `json:"lastChangePasswordTime,omitempty"`
	LastSigninWrongTime    string `json:"lastSigninWrongTime,omitempty"`
	SigninWrongTimes       int    `json:"signinWrongTimes,omitempty"`

	ManagedAccounts     []ManagedAccount `json:"managedAccounts,omitempty"`
	MfaAccounts         []MfaAccount     `json:"mfaAccounts,omitempty"`
	MfaItems            []*MfaItem       `json:"mfaItems,omitempty"`
	MfaRememberDeadline string           `json:"mfaRememberDeadline,omitempty"`
	NeedUpdatePassword  bool             `json:"needUpdatePassword,omitempty"`
	IpWhitelist         string           `json:"ipWhitelist,omitempty"`
	ApplicationScopes   []ConsentRecord  `json:"applicationScopes,omitempty"`
}

// Address is a structured postal address held on a user.
type Address struct {
	Tag     string `json:"tag,omitempty"`
	Line1   string `json:"line1,omitempty"`
	Line2   string `json:"line2,omitempty"`
	City    string `json:"city,omitempty"`
	State   string `json:"state,omitempty"`
	ZipCode string `json:"zipCode,omitempty"`
	Region  string `json:"region,omitempty"`
}

// ManagedAccount is a credential a user delegates for a downstream application.
// Password is secret verify-only material; the handler strips it on read.
type ManagedAccount struct {
	Application string `json:"application,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"-"`
	SigninUrl   string `json:"signinUrl,omitempty"`
}

// MfaAccount is a stored TOTP authenticator entry. SecretKey never serializes.
type MfaAccount struct {
	AccountName string `json:"accountName,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	SecretKey   string `json:"-"`
	Origin      string `json:"origin,omitempty"`
}

// MfaProps is one configured MFA method surfaced to clients. Secret and
// RecoveryCodes are verify-only and stripped from responses.
type MfaProps struct {
	Enabled            bool     `json:"enabled,omitempty"`
	IsPreferred        bool     `json:"isPreferred,omitempty"`
	MfaType            string   `json:"mfaType,omitempty"`
	Secret             string   `json:"-"`
	CountryCode        string   `json:"countryCode,omitempty"`
	URL                string   `json:"url,omitempty"`
	RecoveryCodes      []string `json:"-"`
	MfaRememberInHours int      `json:"mfaRememberInHours,omitempty"`
}

// MfaItem is an organization-defined MFA requirement pinned to the user. It is
// shared with Organization (which declares the org-level requirement set).
type MfaItem struct {
	Name string `json:"name,omitempty"`
	Rule string `json:"rule,omitempty"`
}

// FaceId is a stored face-recognition template for passwordless sign-in.
type FaceId struct {
	Name       string    `json:"name,omitempty"`
	FaceIdData []float64 `json:"faceIdData,omitempty"`
	ImageUrl   string    `json:"imageUrl,omitempty"`
}

// CartItem is a line item retained from v1 (billing lives in Commerce).
type CartItem struct {
	Owner       string  `json:"owner,omitempty"`
	Name        string  `json:"name,omitempty"`
	DisplayName string  `json:"displayName,omitempty"`
	Price       float64 `json:"price,omitempty"`
	Quantity    int     `json:"quantity,omitempty"`
}

// ConsentRecord records the scopes a user granted a given application.
type ConsentRecord struct {
	Application   string   `json:"application,omitempty"`
	GrantedScopes []string `json:"grantedScopes,omitempty"`
}

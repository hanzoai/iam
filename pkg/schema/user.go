// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"encoding/json"
	"strings"

	"github.com/hanzoai/orm"
)

// User is an identity principal — the v2 form of the v1 the legacy surface `user` row,
// re-expressed on hanzoai/orm. It is the authentication entity: the only
// credential material it persists is PasswordHash (a one-way bcrypt digest,
// json:"-" so it never leaves the process) and the legacy hash metadata used
// to migrate rows minted before the bcrypt cutover. The plaintext password is
// never a field on this struct — it arrives on the create/update request,
// is hashed immediately, and is discarded.
//
// The natural/query key is (Owner, Name): Owner is the tenant/organization slug,
// Name is unique within it. The embedded orm.Model[User] supplies the storage
// key, the created/updated timestamps, and the CRUD lifecycle.
type User struct {
	orm.Model[User]

	// Id is the user's STABLE OPAQUE identifier — the value the OIDC `sub` claim
	// carries. It is the v1 the legacy surface per-row UUID (e.g.
	// "e7d7fda0-4c53-4508-9d35-7ec892b7e5d7"), migrated verbatim so a user's `sub`
	// is byte-identical across the cutover: every live session, external reference,
	// and the downstream money-path principal keyed on `sub` survive unchanged. A
	// user minted natively in v2 is assigned a fresh UUID here on create, so the
	// `sub` is ALWAYS a stable opaque id going forward — never the (Owner, Name)
	// pair, which is mutable (a rename would otherwise silently reissue identity).
	//
	// It is distinct from the embedded orm.Model STORAGE KEY — the value the datastore
	// locks and looks a row up by — which is NOT (Owner, Name) for every row: a MIGRATED
	// legacy row is stamped "owner/name" (SetId in the migrator), but a v2-native
	// users.Create'd row is NOT — Create allocates rather than pinning a key, so its
	// storage key is a store-assigned surrogate id (a decimal string like
	// "17847909129933610000001"). (Owner, Name) is therefore the natural/QUERY key
	// (unique, indexed), not necessarily the storage key: resolve a row for a locked
	// write by its REAL key (store.GetUserByName(...).Key().Encode(), which stamps both
	// shapes — see internal/oidc updateUser), never by assuming "owner/name". This Id is
	// a first-class, indexed DOMAIN field; its json tag "id" dominates the promoted
	// orm.Model `Id_` (also "id") by shallower depth, so the persisted record's "id" is
	// this UUID — exactly the v1 shape. A row that carries no Id (a not-yet-assigned
	// pre-cutover user) falls back to the (Owner, Name) subject at mint; every other
	// path resolves `sub`→user by Id.
	Id string `json:"id,omitempty" orm:"index"`

	// Identity / tenancy. (Owner, Name) is the natural key.
	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime"`
	UpdatedTime string `json:"updatedTime"`
	DeletedTime string `json:"deletedTime,omitempty"`

	ExternalId string `json:"externalId,omitempty" orm:"index"`
	Type       string `json:"type,omitempty"`

	// Credential material. PasswordHash is a one-way bcrypt digest and is
	// verify-only. It MUST be persisted (orm serializes the entity to its JSON
	// data column, so a json:"-" field would never be stored — that silently
	// broke login), so it carries a real json tag; the users API redact() strips
	// it (and every other secret) from every response. PasswordType and
	// PasswordSalt describe the digest scheme so rows hashed under the legacy
	// argon2id scheme can still be verified and lazily re-hashed to bcrypt.
	PasswordHash string `json:"passwordHash,omitempty"`
	PasswordType string `json:"passwordType,omitempty"`
	PasswordSalt string `json:"passwordSalt,omitempty"`

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
	// bearer material. AccessSecretHash MUST persist (orm stores via JSON; a
	// json:"-" field is never saved), so it carries a real json tag and the
	// handler's redact() strips it (and AccessSecret + the token fields) before
	// responding.
	AccessKey            string `json:"accessKey,omitempty"`
	AccessSecret         string `json:"accessSecret,omitempty"`
	AccessSecretHash     string `json:"accessSecretHash,omitempty"`
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
	// MfaRememberDigest is the digest of the token held by the ONE browser the
	// deadline above applies to. Without it the deadline is account-wide and "don't
	// ask again on this browser" switches the second factor off everywhere. It is a
	// digest, never the token, so a database dump yields nothing presentable — and it
	// carries a REAL json tag because orm persists via json.Marshal, so `json:"-"`
	// would never be stored (the trap PasswordHash documents above); Mask() strips it
	// from every response instead.
	MfaRememberDigest  string          `json:"mfaRememberDigest,omitempty"`
	NeedUpdatePassword bool            `json:"needUpdatePassword,omitempty"`
	IpWhitelist        string          `json:"ipWhitelist,omitempty"`
	ApplicationScopes  []ConsentRecord `json:"applicationScopes,omitempty"`
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

// ServiceAccount is the User.Type IAM writes for a MACHINE identity — a
// credential with no person behind it. IAM is the authority on what its own rows
// are, so the predicate reading this field lives beside the field rather than in
// a downstream library's opinion of the string. Program below is the sibling
// shape other Hanzo services stamp for the same idea, and Machine accepts both.
const ServiceAccount = "service-account"

// Owner is the User.Type IAM writes for the org's ONE human superuser — the
// person an operator DECLARES in that org's provision document, as against one
// who signed up for themselves ("normal-user") or a machine (ServiceAccount).
//
// It repeats the document's own word for the account deliberately: the class a row
// carries and the `type` its declaration states are one fact, and a synonym here
// would be a second name for it that nothing maps back. User.Owner names the ORG
// this row lives in — a neighbouring field, a different question.
const Owner = "owner"

// Program is the other word, and it is the one a TOKEN carries: the class of a
// machine with no user row, where the registration itself IS the principal.
//
// Its wire spelling is the older of the two, and that is deliberate. A row is read
// by IAM, which knows both words; a token is read by every service that validates
// one, each pinned to its own copy of the predicate — and an earlier account
// library matches ONLY this spelling. Stating the newer word in a token would read
// as a person wherever the reader had not caught up, which is precisely the
// failure the claim exists to end. The wire takes the word everyone knows.
const Program = "application"

// Machine reports whether this row is a machine identity rather than a person.
//
// It decides WHICH LEDGER the principal spends from (store.BillingAccount): a
// machine has no person, so a personal wallet keyed on its name is one no funding
// path can name and it reads $0 forever.
func (u *User) Machine() bool {
	if u == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(u.Type)) {
	case ServiceAccount, Program:
		return true
	}
	return false
}

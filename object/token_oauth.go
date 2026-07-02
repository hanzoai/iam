// Copyright 2024 The Hanzo Authors. All Rights Reserved.
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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hanzoai/iam/i18n"
	"github.com/hanzoai/iam/idp"
	"github.com/hanzoai/iam/util"
)

const (
	hourSeconds          = int(time.Hour / time.Second)
	InvalidRequest       = "invalid_request"
	InvalidClient        = "invalid_client"
	InvalidGrant         = "invalid_grant"
	UnauthorizedClient   = "unauthorized_client"
	UnsupportedGrantType = "unsupported_grant_type"
	InvalidScope         = "invalid_scope"
	EndpointError        = "endpoint_error"
)

var DeviceAuthMap = sync.Map{}

type Code struct {
	Message string `xorm:"varchar(100)" json:"message"`
	Code    string `xorm:"varchar(100)" json:"code"`
}

type TokenWrapper struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type TokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientId  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Nbf       int64    `json:"nbf,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Jti       string   `json:"jti,omitempty"`
}

type DeviceAuthCache struct {
	UserSignIn bool
	UserName   string
	// UserOwner is the approving user's org, captured at approval. The token
	// mint resolves the user in THIS org (not the app's) so a global admin —
	// who lives in conf.AdminOrg, not the app's tenant — resolves to their real
	// godmode identity. Empty on older entries: the mint falls back to the app
	// org, preserving pre-existing single-tenant behavior.
	UserOwner     string
	ApplicationId string
	Scope         string
	RequestAt     time.Time
}

type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUri         string `json:"verification_uri"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// deviceCodeGrantType is the RFC 8628 device authorization grant identifier.
const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

const (
	// DeviceCodeExpirySeconds bounds how long a device_code / user_code pair is
	// valid (RFC 8628 `expires_in`). It is the SINGLE source of truth for the
	// device grant's lifetime — the authorization handler, the token poll, and
	// the discovery response all read it, so they can never drift. 15 minutes
	// gives a human time to open the verification URL, authenticate via SSO,
	// and approve on a second device.
	DeviceCodeExpirySeconds = 900
	// DeviceCodePollInterval is the minimum seconds a client must wait between
	// token-endpoint polls (RFC 8628 `interval`).
	DeviceCodePollInterval = 5
)

// validateResourceURI validates that the resource parameter is a valid absolute URI
// according to RFC 8707 Section 2
func validateResourceURI(resource string) error {
	if resource == "" {
		return nil // empty resource is allowed (backward compatibility)
	}

	parsedURL, err := url.Parse(resource)
	if err != nil {
		return fmt.Errorf("resource must be a valid URI")
	}

	// RFC 8707: The resource parameter must be an absolute URI
	if !parsedURL.IsAbs() {
		return fmt.Errorf("resource must be an absolute URI")
	}

	return nil
}

func ExpireTokenByAccessToken(accessToken string) (bool, *Application, *Token, error) {
	token, err := GetTokenByAccessToken(accessToken)
	if err != nil {
		return false, nil, nil, err
	}
	if token == nil {
		return false, nil, nil, nil
	}

	token.ExpiresIn = 0
	affected, err := ormer.Engine.ID(PK{token.Owner, token.Name}).Cols("expires_in").Update(token)
	if err != nil {
		return false, nil, nil, err
	}

	application, err := getApplication(token.Owner, token.Application)
	if err != nil {
		return false, nil, nil, err
	}

	return affected != 0, application, token, nil
}

func CheckOAuthLogin(clientId string, responseType string, redirectUri string, scope string, state string, lang string) (string, *Application, error) {
	// SECURITY: Only authorization code flow is supported.
	// Implicit flow (token/id_token) has been permanently disabled.
	if responseType != "code" {
		if responseType == "" {
			return i18n.Translate(lang, "token:response_type is required (must be code)"), nil, nil
		}
		return fmt.Sprintf("unsupported response_type: %s — only 'code' is supported", responseType), nil, nil
	}

	application, err := GetApplicationByClientId(clientId)
	if err != nil {
		return "", nil, err
	}

	if application == nil {
		return i18n.Translate(lang, "token:Invalid client_id"), nil, nil
	}

	if !application.IsRedirectUriValid(redirectUri) {
		return fmt.Sprintf(i18n.Translate(lang, "token:Redirect URI: %s doesn't exist in the allowed Redirect URI list"), redirectUri), application, nil
	}

	if !IsScopeValid(scope, application) {
		return i18n.Translate(lang, "token:Invalid scope"), application, nil
	}

	// Mask application for /v1/iam/get-app-login
	application.ClientSecret = ""
	return "", application, nil
}

func GetOAuthCode(userId string, clientId string, provider string, signinMethod string, responseType string, redirectUri string, scope string, state string, nonce string, challenge string, challengeMethod string, resource string, host string, lang string) (*Code, error) {
	user, err := GetUser(userId)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return &Code{
			Message: fmt.Sprintf("general:The user: %s doesn't exist", userId),
			Code:    "",
		}, nil
	}
	if user.IsForbidden {
		return &Code{
			Message: "error: the user is forbidden to sign in, please contact the administrator",
			Code:    "",
		}, nil
	}

	msg, application, err := CheckOAuthLogin(clientId, responseType, redirectUri, scope, state, lang)
	if err != nil {
		return nil, err
	}

	if msg != "" {
		return &Code{
			Message: msg,
			Code:    "",
		}, nil
	}

	// Expand regex/wildcard scopes to concrete scope names.
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return &Code{
			Message: i18n.Translate(lang, "token:Invalid scope"),
			Code:    "",
		}, nil
	}
	scope = expandedScope

	// Validate resource parameter (RFC 8707)
	if err := validateResourceURI(resource); err != nil {
		return &Code{
			Message: err.Error(),
			Code:    "",
		}, nil
	}

	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, err
	}
	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, provider, signinMethod, nonce, scope, resource, host)
	if err != nil {
		return nil, err
	}

	if challenge == "null" {
		challenge = ""
	}
	// SECURITY: Only allow S256 PKCE challenge method.
	// "plain" is rejected to prevent code interception attacks.
	if challengeMethod == "plain" {
		return nil, fmt.Errorf("PKCE challenge method 'plain' is not supported, use 'S256'")
	}
	if challengeMethod == "" || challengeMethod == "null" {
		challengeMethod = "S256"
	}

	token := &Token{
		Owner:               application.Owner,
		Name:                tokenName,
		CreatedTime:         util.GetCurrentTime(),
		Application:         application.Name,
		Organization:        user.Owner,
		User:                user.Name,
		Code:                util.GenerateClientId(),
		AccessToken:         accessToken,
		RefreshToken:        refreshToken,
		ExpiresIn:           int(application.ExpireInHours * float64(hourSeconds)),
		Scope:               scope,
		TokenType:           "Bearer",
		CodeChallenge:       challenge,
		CodeChallengeMethod: challengeMethod,
		CodeIsUsed:          false,
		CodeExpireIn:        time.Now().Add(time.Minute * 5).Unix(),
		Resource:            resource,
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, err
	}

	return &Code{
		Message: "",
		Code:    token.Code,
	}, nil
}

// isPermanentlyDisabledGrant reports whether grantType is a front-channel,
// token-issuing flow this IdP never allows under any application configuration:
// the implicit grant and the bare token / id_token response types. It is the
// single, pure policy point for that decision (decomplected from GetOAuthToken,
// which is DB-coupled). The device authorization grant (RFC 8628) is
// deliberately ABSENT — it is supported and gated per-application via
// GrantTypes, not globally banned.
func isPermanentlyDisabledGrant(grantType string) bool {
	switch grantType {
	case "implicit", "token", "id_token":
		return true
	default:
		return false
	}
}

func GetOAuthToken(grantType string, clientId string, clientSecret string, code string, verifier string, scope string, nonce string, username string, password string, host string, refreshToken string, tag string, avatar string, lang string, subjectToken string, subjectTokenType string, assertion string, clientAssertion string, clientAssertionType string, audience string, resource string, accessKey string, accessSecret string) (interface{}, error) {
	var (
		application *Application
		err         error
		ok          bool
	)

	if clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		ok, application, err = ValidateClientAssertion(clientAssertion, host)
		if err != nil {
			return nil, err
		}

		if !ok || application == nil {
			return &TokenError{
				Error:            InvalidClient,
				ErrorDescription: "client_assertion is invalid",
			}, nil
		}

		clientSecret = application.ClientSecret
		clientId = application.ClientId
	} else {
		application, err = GetApplicationByClientId(clientId)
		if err != nil {
			return nil, err
		}
	}

	if application == nil {
		return &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "client_id is invalid",
		}, nil
	}

	// SECURITY: implicit and the bare token/id_token response types stay
	// permanently disabled — no front-channel token issuance, ever. The device
	// authorization grant (RFC 8628) is SUPPORTED and gated per-application via
	// GrantTypes below; it is the headless/CLI login path (the `dev` CLI, IDE
	// plugins) and never returns a token over a redirect.
	if isPermanentlyDisabledGrant(grantType) {
		return &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: "This grant type has been permanently disabled",
		}, nil
	}

	// SECURITY: the device authorization grant is redeemed ONLY through the
	// device-authorization controller path (handleDeviceCodeToken), which proves
	// the user approved at the verification URI and derives the identity solely
	// from the device-auth cache. This generic path takes a request-supplied
	// username, so it must never mint a device token (doing so would let a caller
	// impersonate any user by sending grant_type=device_code&username=<victim>).
	if grantType == deviceCodeGrantType {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "device_code must be redeemed via the device authorization flow",
		}, nil
	}

	// Check if grantType is allowed in the current application
	if !IsGrantTypeValid(grantType, application.GrantTypes) && tag == "" {
		return &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: fmt.Sprintf("grant_type: %s is not supported in this application", grantType),
		}, nil
	}

	var token *Token
	var tokenError *TokenError
	switch grantType {
	case "authorization_code": // Authorization Code Grant
		token, tokenError, err = GetAuthorizationCodeToken(application, clientSecret, code, verifier, resource)
	case "client_credentials": // Client Credentials Grant
		token, tokenError, err = GetClientCredentialsToken(application, clientSecret, scope, host)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		token, tokenError, err = GetJwtBearerToken(application, assertion, scope, nonce, host)
	case "urn:ietf:params:oauth:grant-type:token-exchange": // Token Exchange Grant (RFC 8693)
		token, tokenError, err = GetTokenExchangeToken(application, clientSecret, subjectToken, subjectTokenType, audience, scope, host)
	case "password": // Resource Owner Password Credentials
		token, tokenError, err = GetPasswordToken(application, username, password, scope, host)
	case "api_key": // API Key Grant — exchange access_key + access_secret for user-bound token
		token, tokenError, err = GetApiKeyToken(application, accessKey, accessSecret, scope, host)
	case "refresh_token":
		refreshToken2, err := RefreshToken(application, grantType, refreshToken, scope, clientId, clientSecret, host)
		if err != nil {
			return nil, err
		}
		return refreshToken2, nil
	}

	if err != nil {
		return nil, err
	}

	if tag == "wechat_miniprogram" {
		// Wechat Mini Program
		token, tokenError, err = GetWechatMiniProgramToken(application, code, host, username, avatar, lang)
		if err != nil {
			return nil, err
		}
	}

	if tokenError != nil {
		return tokenError, nil
	}

	token.CodeIsUsed = true

	_, err = updateUsedByCode(token)
	if err != nil {
		return nil, err
	}

	return tokenWrapperFromToken(token), nil
}

// tokenWrapperFromToken builds the RFC 6749 token response — the single OAuth
// success shape EVERY grant returns. One source, so the device_code, code, and
// refresh grants can never drift in what a client receives.
func tokenWrapperFromToken(token *Token) *TokenWrapper {
	return &TokenWrapper{
		AccessToken:  token.AccessToken,
		IdToken:      token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresIn:    token.ExpiresIn,
		Scope:        token.Scope,
	}
}

func RefreshToken(application *Application, grantType string, refreshToken string, scope string, clientId string, clientSecret string, host string) (interface{}, error) {
	// check parameters
	if grantType != "refresh_token" {
		return &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: "grant_type should be refresh_token",
		}, nil
	}

	var err error
	if application == nil {
		application, err = GetApplicationByClientId(clientId)
		if err != nil {
			return nil, err
		}

		if application == nil {
			return &TokenError{
				Error:            InvalidClient,
				ErrorDescription: "client_id is invalid",
			}, nil
		}
	}

	if clientSecret != "" && subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "client_secret is invalid",
		}, nil
	}

	// check whether the refresh token is valid, and has not expired.
	token, err := GetTokenByRefreshToken(refreshToken)
	if err != nil || token == nil {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token is invalid or revoked",
		}, nil
	}

	// check if the token has been invalidated (e.g., by SSO logout)
	if token.ExpiresIn <= 0 {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token is expired",
		}, nil
	}

	cert, err := getCertByApplication(application)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("cert: %s cannot be found", application.Cert),
		}, nil
	}

	var oldTokenScope string
	if application.TokenFormat == "JWT-Standard" {
		oldToken, err := ParseStandardJwtToken(refreshToken, cert)
		if err != nil {
			return &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: fmt.Sprintf("parse refresh token error: %s", err.Error()),
			}, nil
		}
		oldTokenScope = oldToken.Scope
	} else {
		oldToken, err := ParseJwtToken(refreshToken, cert)
		if err != nil {
			return &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: fmt.Sprintf("parse refresh token error: %s", err.Error()),
			}, nil
		}
		oldTokenScope = oldToken.Scope
	}

	if scope == "" {
		scope = oldTokenScope
	}

	// generate a new token
	user, err := getUser(application.Organization, token.User)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return "", fmt.Errorf("The user: %s doesn't exist", util.GetId(application.Organization, token.User))
	}

	if user.IsForbidden {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user is forbidden to sign in, please contact the administrator",
		}, nil
	}

	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, err
	}

	newAccessToken, newRefreshToken, tokenName, err := generateJwtToken(application, user, "", "", "", scope, "", host)
	if err != nil {
		return &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}

	newToken := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
	}
	_, err = AddToken(newToken)
	if err != nil {
		return nil, err
	}

	_, err = DeleteToken(token)
	if err != nil {
		return nil, err
	}

	return tokenWrapperFromToken(newToken), nil
}

// PkceChallenge: base64-URL-encoded SHA256 hash of verifier, per rfc 7636
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])
	return challenge
}

// IsGrantTypeValid
// Check if grantType is allowed in the current application
// authorization_code is allowed by default
func IsGrantTypeValid(method string, grantTypes []string) bool {
	if method == "authorization_code" {
		return true
	}
	for _, m := range grantTypes {
		if m == method {
			return true
		}
	}
	return false
}

// isRegexScope returns true if the scope string contains regex metacharacters.
func isRegexScope(scope string) bool {
	return strings.ContainsAny(scope, ".*+?^${}()|[]\\")
}

// IsScopeValidAndExpand expands any regex patterns in the space-separated scope string
// against the application's configured scopes. Literal scopes are kept as-is
// after verifying they exist in the allowed list. Regex scopes are matched
// against every allowed scope name; all matches replace the pattern.
// If the application has no defined scopes, the original scope string is
// returned unchanged (backward-compatible behaviour).
// Returns the expanded scope string and whether the scope is valid.
func IsScopeValidAndExpand(scope string, application *Application) (string, bool) {
	if len(application.Scopes) == 0 || scope == "" {
		return scope, true
	}

	allowedNames := make([]string, 0, len(application.Scopes))
	allowedSet := make(map[string]bool, len(application.Scopes))
	for _, s := range application.Scopes {
		allowedNames = append(allowedNames, s.Name)
		allowedSet[s.Name] = true
	}

	seen := make(map[string]bool)
	var expanded []string

	for _, s := range strings.Fields(scope) {
		// Try exact match first.
		if allowedSet[s] {
			if !seen[s] {
				seen[s] = true
				expanded = append(expanded, s)
			}
			continue
		}

		// Not an exact match – if it looks like a regex, try pattern matching.
		if !isRegexScope(s) {
			return "", false
		}

		// Treat as regex pattern – must be a valid regex and match ≥ 1 scope.
		re, err := regexp.Compile("^" + s + "$")
		if err != nil {
			return "", false
		}

		matched := false
		for _, name := range allowedNames {
			if re.MatchString(name) {
				matched = true
				if !seen[name] {
					seen[name] = true
					expanded = append(expanded, name)
				}
			}
		}
		if !matched {
			return "", false
		}
	}

	return strings.Join(expanded, " "), true
}

// IsScopeValid checks whether all space-separated scopes in the scope string
// are defined in the application's Scopes list (including regex expansion).
// If the application has no defined scopes, every scope is considered valid
// (backward-compatible behaviour).
func IsScopeValid(scope string, application *Application) bool {
	_, ok := IsScopeValidAndExpand(scope, application)
	return ok
}

// createGuestUserToken creates a new guest user and returns a token for them
func createGuestUserToken(application *Application, clientSecret string, verifier string) (*Token, *TokenError, error) {
	// Verify client secret if provided
	if clientSecret != "" && subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "client_secret is invalid",
		}, nil
	}

	// Generate a unique guest username
	guestUsername := generateGuestUsername()

	// Generate a random password for the guest user
	guestPassword := util.GenerateId()

	// Get organization
	organization, err := GetOrganization(util.GetId("admin", application.Organization))
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to get organization: %s", err.Error()),
		}, nil
	}
	if organization == nil {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: fmt.Sprintf("organization: %s does not exist", application.Organization),
		}, nil
	}

	// Get initial score
	initScore, err := organization.GetInitScore()
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to get init score: %s", err.Error()),
		}, nil
	}

	// Generate a unique user ID within the confines of the application
	newUserId, idErr := GenerateIdForNewUser(application)
	if idErr != nil {
		// If we fail to generate a unique user ID, we can fallback to a random ID
		newUserId = util.GenerateId()
	}

	// Create the guest user
	guestUser := &User{
		Owner:             application.Organization,
		Name:              guestUsername,
		CreatedTime:       util.GetCurrentTime(),
		Id:                newUserId,
		Type:              "normal-user",
		Password:          guestPassword,
		Tag:               "guest-user",
		DisplayName:       fmt.Sprintf("Guest_%s", guestUsername[:8]),
		Avatar:            "",
		Address:           []string{},
		Email:             "",
		Phone:             "",
		Score:             initScore,
		IsAdmin:           false,
		IsForbidden:       false,
		IsDeleted:         false,
		SignupApplication: application.Name,
		Properties:        map[string]string{},
		RegisterType:      "Guest Signup",
		RegisterSource:    fmt.Sprintf("%s/%s", application.Organization, application.Name),
	}

	// Add the user
	affected, err := AddUser(guestUser, "en")
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to create guest user: %s", err.Error()),
		}, nil
	}
	if !affected {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: "failed to create guest user",
		}, nil
	}

	// Extend user with roles and permissions
	err = ExtendUserWithRolesAndPermissions(guestUser)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to extend user: %s", err.Error()),
		}, nil
	}

	// Generate JWT token
	accessToken, refreshToken, tokenName, err := generateJwtToken(application, guestUser, "", "", "", "", "", "")
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to generate token: %s", err.Error()),
		}, nil
	}

	// Create token object
	token := &Token{
		Owner:         application.Owner,
		Name:          tokenName,
		CreatedTime:   util.GetCurrentTime(),
		Application:   application.Name,
		Organization:  guestUser.Owner,
		User:          guestUser.Name,
		Code:          util.GenerateClientId(),
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		ExpiresIn:     int(application.ExpireInHours * float64(hourSeconds)),
		Scope:         "",
		TokenType:     "Bearer",
		CodeChallenge: "",
		CodeIsUsed:    true,
		CodeExpireIn:  0,
	}

	_, err = AddToken(token)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to add token: %s", err.Error()),
		}, nil
	}

	return token, nil, nil
}

// generateGuestUsername generates a unique username for guest users
func generateGuestUsername() string {
	uid, err := uuid.NewRandom()
	if err != nil {
		// Fallback to a timestamp-based unique ID if UUID generation fails
		return fmt.Sprintf("guest_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("guest_%s", uid.String())
}

// GetAuthorizationCodeToken
// Authorization code flow
func GetAuthorizationCodeToken(application *Application, clientSecret string, code string, verifier string, resource string) (*Token, *TokenError, error) {
	if code == "" {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: "authorization code should not be empty",
		}, nil
	}

	// Handle guest user creation
	if code == "guest-user" {
		return createGuestUserToken(application, clientSecret, verifier)
	}

	token, err := getTokenByCode(code)
	if err != nil {
		return nil, nil, err
	}

	if token == nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("authorization code: [%s] is invalid", code),
		}, nil
	}

	if token.CodeIsUsed {
		// anti replay attacks
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("authorization code has been used for token: [%s]", token.GetId()),
		}, nil
	}

	if token.CodeChallenge != "" {
		// RFC 7636: verify code_verifier against stored code_challenge
		// SECURITY: Only S256 is supported. Reject "plain" challenge method
		// to prevent interception attacks where code_challenge == code_verifier.
		if token.CodeChallengeMethod == "plain" {
			return nil, &TokenError{
				Error:            InvalidRequest,
				ErrorDescription: "PKCE challenge method 'plain' is not supported, use 'S256'",
			}, nil
		}
		challengeValid := (pkceChallenge(verifier) == token.CodeChallenge)
		if !challengeValid {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "code_verifier does not match code_challenge",
			}, nil
		}
	}

	if subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		// when using PKCE, the Client Secret can be empty,
		// but if it is provided, it must be accurate.
		if token.CodeChallenge == "" {
			return nil, &TokenError{
				Error:            InvalidClient,
				ErrorDescription: fmt.Sprintf("client_secret is invalid for application: [%s], token.CodeChallenge: empty", application.GetId()),
			}, nil
		} else {
			if clientSecret != "" {
				return nil, &TokenError{
					Error:            InvalidClient,
					ErrorDescription: fmt.Sprintf("client_secret is invalid for application: [%s], token.CodeChallenge: [%s]", application.GetId(), token.CodeChallenge),
				}, nil
			}
		}
	}

	if application.Name != token.Application {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("the token is for wrong application (client_id), application.Name: [%s], token.Application: [%s]", application.Name, token.Application),
		}, nil
	}

	// RFC 8707: Validate resource parameter matches the one in the authorization request
	if resource != token.Resource {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("resource parameter does not match authorization request, expected: [%s], got: [%s]", token.Resource, resource),
		}, nil
	}

	nowUnix := time.Now().Unix()
	if nowUnix > token.CodeExpireIn {
		// code must be used within 5 minutes
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("authorization code has expired, nowUnix: [%s], token.CodeExpireIn: [%s]", time.Unix(nowUnix, 0).Format(time.RFC3339), time.Unix(token.CodeExpireIn, 0).Format(time.RFC3339)),
		}, nil
	}
	return token, nil, nil
}

// GetPasswordToken
// Resource Owner Password Credentials flow
func GetPasswordToken(application *Application, username string, password string, scope string, host string) (*Token, *TokenError, error) {
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return nil, &TokenError{
			Error:            InvalidScope,
			ErrorDescription: "the requested scope is invalid or not defined in the application",
		}, nil
	}
	scope = expandedScope

	user, err := GetUserByFields(application.Organization, username)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user does not exist",
		}, nil
	}

	if user.Ldap != "" {
		err = CheckLdapUserPassword(user, password, "en")
	} else {
		// For OAuth users who don't have a password set, they cannot use password grant type
		if user.Password == "" {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "OAuth users cannot use password grant type, please use authorization code flow",
			}, nil
		}
		err = CheckPassword(user, password, "en")
	}
	if err != nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("invalid username or password: %s", err.Error()),
		}, nil
	}

	if user.IsForbidden {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user is forbidden to sign in, please contact the administrator",
		}, nil
	}

	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, nil, err
	}

	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, "", "", "", scope, "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}
	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		CodeIsUsed:   true,
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}

	return token, nil, nil
}

// GetApiKeyToken exchanges a user's API key (access_key + access_secret) for
// a user-bound OAuth token. This enables machine-to-machine authentication
// using long-lived API keys instead of username/password (ROPC).
func GetApiKeyToken(application *Application, accessKey string, accessSecret string, scope string, host string) (*Token, *TokenError, error) {
	if accessKey == "" || accessSecret == "" {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "access_key and access_secret are required",
		}, nil
	}

	user, err := GetUserByAccessKey(accessKey)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "invalid access_key",
		}, nil
	}

	// VerifyUserAccessSecret is the single choke point for secret verification:
	// argon2id compare for a service account (hashed secret at rest), or
	// constant-time plaintext compare for a legacy hk- user. Both are
	// constant-time; a revoked/empty credential fails closed.
	if !VerifyUserAccessSecret(user, accessSecret) {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "invalid access_secret",
		}, nil
	}

	if user.IsForbidden {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user is forbidden to sign in, please contact the administrator",
		}, nil
	}

	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, nil, err
	}

	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, "", "api_key", "", scope, "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}
	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		CodeIsUsed:   true,
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}

	return token, nil, nil
}

// GetClientCredentialsToken
// Client Credentials flow
func GetClientCredentialsToken(application *Application, clientSecret string, scope string, host string) (*Token, *TokenError, error) {
	if subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "client_secret is invalid",
		}, nil
	}
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return nil, &TokenError{
			Error:            InvalidScope,
			ErrorDescription: "the requested scope is invalid or not defined in the application",
		}, nil
	}
	scope = expandedScope
	// JWT `owner` claim must equal the tenant org slug so downstream
	// services (KMS, Gateway, etc.) can scope per-tenant via
	// `owner == {org}` checks. `application.Owner` is the Casdoor
	// maintainer namespace (always "admin" in our deployments) — using
	// it leaks every machine identity into the admin namespace and
	// breaks per-tenant org scoping (KMS canActOnOrg, F7 regression).
	// `application.Organization` is the tenant slug per CLAUDE.md
	// contract ("Downstream services extract owner from JWT claims").
	nullUser := &User{
		Owner: application.Organization,
		Id:    application.GetId(),
		Name:  application.Name,
		Type:  "application",
	}

	accessToken, _, tokenName, err := generateJwtToken(application, nullUser, "", "", "", scope, "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}
	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: application.Organization,
		User:         nullUser.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		CodeIsUsed:   true,
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}

	return token, nil, nil
}

// GetImplicitToken
// Implicit flow
func GetImplicitToken(application *Application, username string, scope string, nonce string, host string) (*Token, *TokenError, error) {
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return nil, &TokenError{
			Error:            InvalidScope,
			ErrorDescription: "the requested scope is invalid or not defined in the application",
		}, nil
	}
	scope = expandedScope

	user, err := GetUserByFields(application.Organization, username)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user does not exist",
		}, nil
	}
	if user.IsForbidden {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user is forbidden to sign in, please contact the administrator",
		}, nil
	}

	token, err := GetTokenByUser(application, user, scope, nonce, host)
	if err != nil {
		return nil, nil, err
	}
	return token, nil, nil
}

// GetJwtBearerToken
// RFC 7523
func GetJwtBearerToken(application *Application, assertion string, scope string, nonce string, host string) (*Token, *TokenError, error) {
	ok, claims, err := ValidateJwtAssertion(assertion, application, host)
	if err != nil || !ok {
		if err != nil {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: err.Error(),
			}, err
		}

		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("assertion (JWT) is invalid for application: [%s]", application.GetId()),
		}, nil
	}

	return GetImplicitToken(application, claims.Subject, scope, nonce, host)
}

func ValidateJwtAssertion(clientAssertion string, application *Application, host string) (bool, *Claims, error) {
	_, originBackend := getOriginFromHost(host)

	clientCert, err := getCert(application.Owner, application.ClientCert)
	if err != nil {
		return false, nil, err
	}
	if clientCert == nil {
		return false, nil, fmt.Errorf("client certificate is not configured for application: [%s]", application.GetId())
	}

	claims, err := ParseJwtToken(clientAssertion, clientCert)
	if err != nil {
		return false, nil, err
	}

	if !slices.Contains(application.RedirectUris, claims.Issuer) {
		return false, nil, nil
	}

	if !slices.Contains(claims.Audience, fmt.Sprintf("%s/v1/iam/oauth/access_token", originBackend)) {
		return false, nil, nil
	}

	return true, claims, nil
}

func ValidateClientAssertion(clientAssertion string, host string) (bool, *Application, error) {
	token, err := ParseJwtTokenWithoutValidation(clientAssertion)
	if err != nil {
		return false, nil, err
	}

	clientId, err := token.Claims.GetSubject()
	if err != nil {
		return false, nil, err
	}

	application, err := GetApplicationByClientId(clientId)
	if err != nil {
		return false, nil, err
	}
	if application == nil {
		return false, nil, fmt.Errorf("application not found for client: [%s]", clientId)
	}

	ok, _, err := ValidateJwtAssertion(clientAssertion, application, host)
	if err != nil {
		return false, application, err
	}
	if !ok {
		return false, application, nil
	}

	return true, application, nil
}

// GetTokenByUser
// Implicit flow
func GetTokenByUser(application *Application, user *User, scope string, nonce string, host string) (*Token, error) {
	err := ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, "", "", nonce, scope, "", host)
	if err != nil {
		return nil, err
	}

	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		CodeIsUsed:   true,
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// GetDeviceCodeToken issues a token for the user who approved a device
// authorization request (RFC 8628). Identity, scope, and approval all come from
// deviceAuth — the device-auth cache entry the controller consumed — and NEVER
// from request parameters: a caller cannot pass a username. The function is
// fail-closed and safe regardless of caller — it re-asserts the authorization
// was approved (deviceAuthApprovedError) before minting, so the "the controller
// already verified this" precondition is enforced here, not merely assumed.
// There is deliberately no secret/password check: the human authenticating and
// approving interactively at the verification URI is the authentication.
func GetDeviceCodeToken(application *Application, deviceAuth *DeviceAuthCache, nonce string, host string) (*TokenWrapper, *TokenError, error) {
	if te := deviceAuthApprovedError(deviceAuth); te != nil {
		return nil, te, nil
	}

	// RFC 8628 §3.4: a device_code is bound to the client it was issued to.
	// Reject redemption by a different client — otherwise an approval for app A
	// could be redeemed as app B (confused deputy: wrong audience, and via a
	// cross-org name collision, e.g. the same-named superuser in every brand,
	// a different/elevated principal).
	if te := deviceClientMismatchError(application, deviceAuth); te != nil {
		return nil, te, nil
	}

	// Per-application grant gate, enforced here directly (not via the generic
	// path's tag-bypassable check) so an app that never enabled device_code
	// cannot mint device tokens.
	if !IsGrantTypeValid(deviceCodeGrantType, application.GrantTypes) {
		return nil, &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: fmt.Sprintf("grant_type: %s is not supported in this application", deviceCodeGrantType),
		}, nil
	}

	expandedScope, ok := IsScopeValidAndExpand(deviceAuth.Scope, application)
	if !ok {
		return nil, &TokenError{
			Error:            InvalidScope,
			ErrorDescription: "the requested scope is invalid or not defined in the application",
		}, nil
	}

	// Resolve the approver in the org captured at approval (deviceAuth.UserOwner),
	// falling back to the app's org for older cache entries. For a normal
	// single-tenant approval the two are identical; for a global admin the
	// captured org is conf.AdminOrg, so the mint finds their godmode identity
	// instead of failing to find a non-existent same-named user in the app org.
	// This is safe because DeviceApprovalCrossTenantError already gated approval:
	// a non-global-admin only reaches here with UserOwner == application.Organization.
	lookupOrg := deviceAuth.UserOwner
	if lookupOrg == "" {
		lookupOrg = application.Organization
	}
	user, err := GetUserByFields(lookupOrg, deviceAuth.UserName)
	if err != nil {
		return nil, nil, err
	}
	if te := deviceCodeUserError(user); te != nil {
		return nil, te, nil
	}

	token, err := GetTokenByUser(application, user, expandedScope, nonce, host)
	if err != nil {
		return nil, nil, err
	}

	// Return the standard OAuth response shape (access_token/token_type/…), not
	// the raw Token record — the dev CLI / any RFC 8628 client parses this.
	return tokenWrapperFromToken(token), nil, nil
}

// deviceClientMismatchError enforces RFC 8628 §3.4: the device_code must be
// redeemed by the same client it was issued to. deviceAuth.ApplicationId is
// captured at the device-authorization request; reject when the redeeming
// application differs. Pure (no DB) so the binding is unit-testable.
func deviceClientMismatchError(application *Application, deviceAuth *DeviceAuthCache) *TokenError {
	if application == nil || deviceAuth == nil || application.GetId() != deviceAuth.ApplicationId {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the device_code was not issued to this client",
		}
	}
	return nil
}

// deviceAuthApprovedError returns a TokenError unless deviceAuth represents a
// completed, approved device authorization (signed in, with a resolved user).
// Pure (no DB) so the approval gate is unit-testable. This is the defense that
// makes GetDeviceCodeToken safe regardless of how it is reached.
func deviceAuthApprovedError(deviceAuth *DeviceAuthCache) *TokenError {
	if deviceAuth == nil || !deviceAuth.UserSignIn || deviceAuth.UserName == "" {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the device authorization has not been approved",
		}
	}
	return nil
}

// deviceCodeUserError returns the TokenError that forbids issuing a device-grant
// token for user (unknown or sign-in-forbidden), or nil when issuance may
// proceed. Pure (no DB) so the issuance policy is unit-testable independently of
// GetUserByFields's storage coupling.
func deviceCodeUserError(user *User) *TokenError {
	if user == nil {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user does not exist",
		}
	}
	if user.IsForbidden {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user is forbidden to sign in, please contact the administrator",
		}
	}
	return nil
}

// DeviceApprovalCrossTenantError refuses a device approval when the approving
// user's organization differs from the organization that owns the device
// authorization's application. The device_code carries the app it was issued
// for (DeviceAuthCache.ApplicationId, resolved to deviceApp); the approving
// identity comes from the browser session. A user in org A must never be able
// to approve a device sign-in bound to an app in org B (cross-tenant confused
// deputy — e.g. the same-named superuser seeded in every brand). This is also
// the invariant the downstream token mint depends on: GetDeviceCodeToken looks
// the approver up via GetUserByFields(deviceApp.Organization, UserName), which
// only resolves when the approver actually belongs to that org. Pure (no DB) so
// the tenant boundary is unit-testable. Fail-closed: a nil user/app, or an app
// with an empty organization, refuses.
func DeviceApprovalCrossTenantError(user *User, deviceApp *Application) error {
	if user == nil || deviceApp == nil || deviceApp.Organization == "" {
		return fmt.Errorf("the device authorization could not be resolved")
	}
	// Godmode: a GLOBAL admin (a user in conf.AdminOrg) may approve a device
	// sign-in for any org's app — acting across every tenant is exactly what
	// global-admin means, and it is precisely the account operators use to sign
	// a CLI into any brand's app. This is NOT the same as the org-scoped
	// same-named superuser (e.g. zoo's "z") the guard blocks: that user is in a
	// TENANT org, IsGlobalAdmin() is false for it, and it stays refused below.
	if user.IsGlobalAdmin() {
		return nil
	}
	if user.Owner != deviceApp.Organization {
		return fmt.Errorf("cross-tenant device approval refused: your organization may not approve this device sign-in")
	}
	return nil
}

// ResolveDeviceApprovalApp resolves the application a pending device user_code
// is bound to, for the anonymous GET /v1/iam/get-app-login device lookup. It is
// deliberately NON-DIFFERENTIAL: every failure mode — unknown code, expired
// code, or an unresolvable/absent application — collapses to (nil, false) so the
// caller can render ONE generic error and never leak exists-vs-not or the bound
// app/org to a caller grinding user_codes. Holding a valid, unexpired user_code
// IS the RFC 8628 proof the legit SPA presents to render the approval page, so
// the (app, true) path returns the app; the 40-bit crypto user_code and the
// per-IP throttle are the backstops against guessing one. The load and expiry
// checks are pure (no DB), so the non-differential contract is unit-testable.
func ResolveDeviceApprovalApp(userCode string) (*Application, bool) {
	cached, ok := DeviceAuthMap.Load(userCode)
	if !ok {
		return nil, false
	}
	deviceAuth, ok := cached.(DeviceAuthCache)
	if !ok {
		return nil, false
	}
	if deviceAuth.RequestAt.Add(time.Second * DeviceCodeExpirySeconds).Before(time.Now()) {
		return nil, false
	}
	application, err := GetApplication(deviceAuth.ApplicationId)
	if err != nil || application == nil {
		return nil, false
	}
	return application, true
}

// GetUserTokenForAudience mints a short-lived, user-bound JWT for an EXPLICIT
// audience. It is the server-side primitive a confidential, trusted client
// (e.g. hanzo-console) uses to obtain a token it forwards to a resource server
// (e.g. commerce) that derives the user's org from the verified `owner` claim
// — the SSR analogue of a browser holding its own IAM token.
//
// It is identical to GetTokenByUser except the audience is set explicitly via
// the RFC 8707 `resource` claim instead of defaulting to the minting
// application's clientId. This decouples the token's audience from WHICH app
// minted it, so the resource server's fixed audience allowlist
// (commerce IAM_ACCEPTED_AUDIENCES) matches deterministically. An empty
// `audience` falls back to the default (clientId / shared-org) audience, so
// callers that don't care get GetTokenByUser's behavior.
//
// The token carries the user's real `owner` (org) claim, so the resource
// server scopes strictly to THAT org — there is no cross-tenant widening here:
// the audience only names the trusted client, never the billed subject.
func GetUserTokenForAudience(application *Application, user *User, audience string, scope string, host string) (*Token, error) {
	err := ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, "", "", "", scope, audience, host)
	if err != nil {
		return nil, err
	}

	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		CodeIsUsed:   true,
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// GetWechatMiniProgramToken
// Wechat Mini Program flow
func GetWechatMiniProgramToken(application *Application, code string, host string, username string, avatar string, lang string) (*Token, *TokenError, error) {
	mpProvider := GetWechatMiniProgramProvider(application)
	if mpProvider == nil {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "the application does not support wechat mini program",
		}, nil
	}
	provider, err := GetProvider(util.GetId("admin", mpProvider.Name))
	if err != nil {
		return nil, nil, err
	}

	mpIdp := idp.NewWeChatMiniProgramIdProvider(provider.ClientId, provider.ClientSecret)
	session, err := mpIdp.GetSessionByCode(code)
	if err != nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("get wechat mini program session error: %s", err.Error()),
		}, nil
	}

	openId, unionId := session.Openid, session.Unionid
	if openId == "" && unionId == "" {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: "the wechat mini program session is invalid",
		}, nil
	}
	user, err := getUserByWechatId(application.Organization, openId, unionId)
	if err != nil {
		return nil, nil, err
	}

	if user == nil {
		if !application.EnableSignUp {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "the application does not allow to sign up new account",
			}, nil
		}
		// Add new user
		var name string
		if CheckUsername(username, lang) == "" {
			name = username
		} else {
			name = fmt.Sprintf("wechat-%s", openId)
		}

		// Generate a unique user ID within the confines of the application
		newUserId, idErr := GenerateIdForNewUser(application)
		if idErr != nil {
			// If we fail to generate a unique user ID, we can fallback to a random ID
			newUserId = util.GenerateId()
		}

		user = &User{
			Owner:             application.Organization,
			Id:                newUserId,
			Name:              name,
			Avatar:            avatar,
			SignupApplication: application.Name,
			WeChat:            openId,
			Type:              "normal-user",
			CreatedTime:       util.GetCurrentTime(),
			IsAdmin:           false,
			IsForbidden:       false,
			IsDeleted:         false,
			Properties: map[string]string{
				UserPropertiesWechatOpenId:  openId,
				UserPropertiesWechatUnionId: unionId,
			},
		}
		_, err = AddUser(user, "en")
		if err != nil {
			return nil, nil, err
		}
	}

	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, nil, err
	}

	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, "", "", "", "", "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}

	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         session.SessionKey, // a trick, because miniprogram does not use the code, so use the code field to save the session_key
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        "",
		TokenType:    "Bearer",
		CodeIsUsed:   true,
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}
	return token, nil, nil
}

// GetTokenExchangeToken
// Token Exchange Grant (RFC 8693)
// Exchanges a subject token for a new token with different audience or scope
func GetTokenExchangeToken(application *Application, clientSecret string, subjectToken string, subjectTokenType string, audience string, scope string, host string) (*Token, *TokenError, error) {
	// Verify client secret
	if subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "client_secret is invalid",
		}, nil
	}

	// Validate subject_token parameter
	if subjectToken == "" {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: "subject_token is required",
		}, nil
	}

	// Validate subject_token_type parameter
	// RFC 8693 defines standard token type identifiers
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token" // Default to access_token
	}

	// Support common token types
	supportedTokenTypes := []string{
		"urn:ietf:params:oauth:token-type:access_token",
		"urn:ietf:params:oauth:token-type:jwt",
		"urn:ietf:params:oauth:token-type:id_token",
	}

	isValidTokenType := false
	for _, tokenType := range supportedTokenTypes {
		if subjectTokenType == tokenType {
			isValidTokenType = true
			break
		}
	}

	if !isValidTokenType {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: fmt.Sprintf("unsupported subject_token_type: %s", subjectTokenType),
		}, nil
	}

	// Get certificate for token validation
	cert, err := getCertByApplication(application)
	if err != nil {
		return nil, nil, err
	}
	if cert == nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("cert: %s cannot be found", application.Cert),
		}, nil
	}

	// Parse and validate the subject token
	var subjectOwner, subjectName, subjectScope string
	if application.TokenFormat == "JWT-Standard" {
		standardClaims, err := ParseStandardJwtToken(subjectToken, cert)
		if err != nil {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: fmt.Sprintf("invalid subject_token: %s", err.Error()),
			}, nil
		}
		subjectOwner = standardClaims.Owner
		subjectName = standardClaims.Name
		subjectScope = standardClaims.Scope
	} else {
		claims, err := ParseJwtToken(subjectToken, cert)
		if err != nil {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: fmt.Sprintf("invalid subject_token: %s", err.Error()),
			}, nil
		}
		subjectOwner = claims.Owner
		subjectName = claims.Name
		subjectScope = claims.Scope
	}

	// Get the user from the subject token
	user, err := getUser(subjectOwner, subjectName)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("user from subject_token does not exist: %s", util.GetId(subjectOwner, subjectName)),
		}, nil
	}

	if user.IsForbidden {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user is forbidden to sign in, please contact the administrator",
		}, nil
	}

	// Handle scope parameter
	// If scope is not provided, use the scope from the subject token
	// If scope is provided, it should be a subset of the subject token's scope (downscoping)
	if scope == "" {
		scope = subjectScope
	} else {
		// Validate scope downscoping (basic implementation)
		// In a production environment, you would implement more sophisticated scope validation
		if subjectScope != "" {
			subjectScopes := strings.Split(subjectScope, " ")
			requestedScopes := strings.Split(scope, " ")
			for _, requestedScope := range requestedScopes {
				if requestedScope == "" {
					continue // Skip empty strings
				}
				found := false
				for _, existingScope := range subjectScopes {
					if existingScope != "" && requestedScope == existingScope {
						found = true
						break
					}
				}
				if !found {
					return nil, &TokenError{
						Error:            InvalidScope,
						ErrorDescription: fmt.Sprintf("requested scope '%s' is not in subject token's scope", requestedScope),
					}, nil
				}
			}
		}
	}

	// Extend user with roles and permissions
	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, nil, err
	}

	// Generate new JWT token
	accessToken, refreshToken, tokenName, err := generateJwtToken(application, user, "", "", "", scope, "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}

	// Create token object
	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		CodeIsUsed:   true,
	}

	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}

	return token, nil, nil
}

func GetAccessTokenByUser(user *User, host string) (string, error) {
	application, err := GetApplicationByUser(user)
	if err != nil {
		return "", err
	}
	if application == nil {
		return "", fmt.Errorf("the application for user %s is not found", user.Id)
	}

	token, err := GetTokenByUser(application, user, "profile", "", host)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

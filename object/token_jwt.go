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
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/beego/v2/core/logs"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/util"
)

type Claims struct {
	*User
	TokenType string `json:"tokenType,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Tag       string `json:"tag"`
	Scope     string `json:"scope,omitempty"`
	// the `azp` (Authorized Party) claim. Optional. See https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	Azp      string `json:"azp,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Project is the caller's org DEFAULT project (the Project row with
	// IsDefault=true for the user's org). The gateway mints X-Project-Id from it
	// (empty ⟹ default scope ⟹ header omitted). Resolved once at mint time and
	// threaded into every token format alongside `organization`.
	Project string `json:"project,omitempty"`

	SigninMethod string `json:"signinMethod,omitempty"`
	jwt.RegisteredClaims
}

type UserShort struct {
	Owner string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name  string `xorm:"varchar(100) notnull pk" json:"name"`

	Id            string `xorm:"varchar(100) index" json:"id"`
	DisplayName   string `xorm:"varchar(100)" json:"displayName"`
	Avatar        string `xorm:"varchar(500)" json:"avatar"`
	Email         string `xorm:"varchar(100) index" json:"email"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Phone         string `xorm:"varchar(100) index" json:"phone"`
}

type UserStandard struct {
	Owner string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name  string `xorm:"varchar(100) notnull pk" json:"preferred_username,omitempty"`

	Id            string `xorm:"varchar(100) index" json:"id"`
	DisplayName   string `xorm:"varchar(100)" json:"name,omitempty"`
	Avatar        string `xorm:"varchar(500)" json:"picture,omitempty"`
	Email         string `xorm:"varchar(100) index" json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Phone         string `xorm:"varchar(100) index" json:"phone,omitempty"`
}

// UserWithoutThirdIdp is the identity + authorization projection embedded in the
// default "JWT" access token. It carries exactly what a bearer needs: identity
// (sub/name/owner/email), the org (owner + the wrapper's `organization` claim),
// the authorization grant (isAdmin + roles/permissions/groups) and the billing
// tier (Properties, filtered to billingProps). Everything else is dropped:
// credential material (password/passwordSalt/passwordType/totpSecret/
// recoveryCodes/hash), the full profile (avatar/address/education/social-IdP
// links), audit + gamification fields, managedAccounts and the console
// UI-preferences blob that otherwise dominated Properties.
//
// Two invariants fall out by construction: (1) the token never leaks
// credentials, and (2) it stays inside the edge request-header buffer —
// api.hanzo.ai answers HTTP 431 "Too big request header" on oversized headers,
// which locked tenants out of /v1/chat/completions, billing CRUD and search.
type UserWithoutThirdIdp struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`

	Id            string `json:"id,omitempty"`
	Type          string `json:"type,omitempty"`
	DisplayName   string `json:"displayName,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Phone         string `json:"phone,omitempty"`

	IsAdmin bool `json:"isAdmin,omitempty"`

	Roles       []roleRef         `json:"roles,omitempty"`
	Permissions []roleRef         `json:"permissions,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

type ClaimsShort struct {
	*UserShort
	// Organization mirrors the embedded user's `owner` under the standard OIDC
	// claim name. `owner` is the canonical org claim (gateway → X-Org-Id); this
	// alias lets consumers read either, identically across every token format.
	Organization string `json:"organization,omitempty"`
	// Project is the org's default project; see Claims.Project.
	Project   string `json:"project,omitempty"`
	TokenType string `json:"tokenType,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Azp       string `json:"azp,omitempty"`
	Provider  string `json:"provider,omitempty"`

	SigninMethod string `json:"signinMethod,omitempty"`
	jwt.RegisteredClaims
}

type OIDCAddress struct {
	Formatted     string `json:"formatted"`
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

type ClaimsWithoutThirdIdp struct {
	*UserWithoutThirdIdp
	// Organization mirrors the embedded user's `owner` (see ClaimsShort).
	Organization string `json:"organization,omitempty"`
	// Project is the org's default project; see Claims.Project.
	Project   string `json:"project,omitempty"`
	TokenType string `json:"tokenType,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Tag       string `json:"tag"`
	Scope     string `json:"scope,omitempty"`
	Azp       string `json:"azp,omitempty"`
	Provider  string `json:"provider,omitempty"`

	SigninMethod string `json:"signinMethod,omitempty"`
	jwt.RegisteredClaims
}

func getShortUser(user *User) *UserShort {
	res := &UserShort{
		Owner: user.Owner,
		Name:  user.Name,

		Id:            user.Id,
		DisplayName:   user.DisplayName,
		Avatar:        user.Avatar,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Phone:         user.Phone,
	}
	return res
}

func getStandardUser(user *User) *UserStandard {
	res := &UserStandard{
		Owner: user.Owner,
		Name:  user.Name,

		Id:            user.Id,
		DisplayName:   user.DisplayName,
		Avatar:        user.Avatar,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Phone:         user.Phone,
	}
	return res
}

// roleRef is the minimal role/permission shape carried in an access token.
// commerce reads role NAMES (auth.FlexRoles) and IAM re-fetches the full user
// — roles included — from the DB when it refreshes a token (see getUser in
// GetOAuthToken), so the token never needs the full Role/Permission record.
// Emitting only owner+name keeps the token BOUNDED even for role-heavy users
// and still deserializes cleanly back into Claims{*User}'s []*Role/[]*Permission
// on ParseJwtToken.
type roleRef struct {
	Owner string `json:"owner,omitempty"`
	Name  string `json:"name,omitempty"`
}

func roleRefs(roles []*Role) []roleRef {
	out := make([]roleRef, 0, len(roles))
	for _, r := range roles {
		if r != nil {
			out = append(out, roleRef{Owner: r.Owner, Name: r.Name})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func permissionRefs(perms []*Permission) []roleRef {
	out := make([]roleRef, 0, len(perms))
	for _, p := range perms {
		if p != nil {
			out = append(out, roleRef{Owner: p.Owner, Name: p.Name})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// billingProps is the allowlist of user Properties a bearer token carries. The
// console UI-preferences blob and other free-form properties are dropped to keep
// the token bounded; `tier` is read by commerce for plan gating.
var billingProps = map[string]bool{"tier": true}

// filterProps returns only the allowlisted Properties, or nil so the claim is
// omitted entirely when none are present.
func filterProps(in map[string]string) map[string]string {
	var out map[string]string
	for k := range billingProps {
		if v, ok := in[k]; ok {
			if out == nil {
				out = make(map[string]string, len(billingProps))
			}
			out[k] = v
		}
	}
	return out
}

func getUserWithoutThirdIdp(user *User) *UserWithoutThirdIdp {
	return &UserWithoutThirdIdp{
		Owner: user.Owner,
		Name:  user.Name,

		Id:            user.Id,
		Type:          user.Type,
		DisplayName:   user.DisplayName,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Phone:         user.Phone,

		IsAdmin: user.IsAdmin,

		Roles:       roleRefs(user.Roles),
		Permissions: permissionRefs(user.Permissions),
		Groups:      user.Groups,
		Properties:  filterProps(user.Properties),
	}
}

func getShortClaims(claims Claims) ClaimsShort {
	res := ClaimsShort{
		UserShort:        getShortUser(claims.User),
		Organization:     claims.User.Owner,
		Project:          claims.Project,
		TokenType:        claims.TokenType,
		Nonce:            claims.Nonce,
		Scope:            claims.Scope,
		RegisteredClaims: claims.RegisteredClaims,
		Azp:              claims.Azp,
		SigninMethod:     claims.SigninMethod,
		Provider:         claims.Provider,
	}
	return res
}

func getClaimsWithoutThirdIdp(claims Claims) ClaimsWithoutThirdIdp {
	res := ClaimsWithoutThirdIdp{
		UserWithoutThirdIdp: getUserWithoutThirdIdp(claims.User),
		Organization:        claims.User.Owner,
		Project:             claims.Project,
		TokenType:           claims.TokenType,
		Nonce:               claims.Nonce,
		Tag:                 claims.Tag,
		Scope:               claims.Scope,
		RegisteredClaims:    claims.RegisteredClaims,
		Azp:                 claims.Azp,
		SigninMethod:        claims.SigninMethod,
		Provider:            claims.Provider,
	}
	return res
}

// getUserFieldValue gets the value of a user field by name, handling special cases like Roles and Permissions
func getUserFieldValue(user *User, fieldName string) (interface{}, bool) {
	if user == nil {
		return nil, false
	}

	// Handle special fields that need conversion
	switch fieldName {
	case "Roles":
		return getUserRoleNames(user), true
	case "Permissions":
		return getUserPermissionNames(user), true
	case "permissionNames":
		permissionNames := []string{}
		for _, val := range user.Permissions {
			permissionNames = append(permissionNames, val.Name)
		}
		return permissionNames, true
	}

	// Handle Properties fields (e.g., Properties.my_field)
	if strings.HasPrefix(fieldName, "Properties.") {
		parts := strings.Split(fieldName, ".")
		if len(parts) == 2 {
			propName := parts[1]
			if user.Properties != nil {
				if value, exists := user.Properties[propName]; exists {
					return value, true
				}
			}
		}
		return nil, false
	}

	// Use reflection to get the field value
	userValue := reflect.ValueOf(user).Elem()
	userField := userValue.FieldByName(fieldName)
	if userField.IsValid() {
		return userField.Interface(), true
	}

	return nil, false
}

func getClaimsCustom(claims Claims, tokenField []string, tokenAttributes []*JwtItem) jwt.MapClaims {
	res := make(jwt.MapClaims)

	userValue := reflect.ValueOf(claims.User).Elem()

	// Always include standard JWT registered claims
	res["iss"] = claims.RegisteredClaims.Issuer
	res["sub"] = claims.RegisteredClaims.Subject
	res["aud"] = claims.RegisteredClaims.Audience
	res["exp"] = claims.RegisteredClaims.ExpiresAt
	res["nbf"] = claims.RegisteredClaims.NotBefore
	res["iat"] = claims.RegisteredClaims.IssuedAt
	res["jti"] = claims.RegisteredClaims.ID

	// Always include tokenType (essential metadata)
	res["tokenType"] = claims.TokenType

	// Always include the org claim, independent of the application's selected
	// token fields. `owner` is the canonical org/tenant claim that the gateway
	// maps to X-Org-Id (2026-03-27 header convention) and that migrated clients
	// read; `organization` mirrors it under the standard name. The other JWT
	// formats (JWT/JWT-Empty/JWT-Standard) already carry `owner` via the
	// embedded user struct — JWT-Custom only emits explicitly-selected fields,
	// so the org would otherwise be dropped here.
	if claims.User != nil {
		res["owner"] = claims.User.Owner
		res["organization"] = claims.User.Owner
	}

	// Include the org's default project when set. Omitted when empty so the
	// gateway's absent-⟹-default contract holds (mirrors the omitempty struct
	// formats and matches how `owner`/`organization` ride here for JWT-Custom).
	if claims.Project != "" {
		res["project"] = claims.Project
	}

	// Always include azp if present (authorized party)
	if claims.Azp != "" {
		res["azp"] = claims.Azp
	}

	// Always include nonce and scope as they are built-in OAuth/OIDC fields (even if empty)
	res["nonce"] = claims.Nonce
	res["scope"] = claims.Scope

	// Create a map for quick lookup of selected token fields
	selectedFields := make(map[string]bool)
	for _, field := range tokenField {
		selectedFields[field] = true
	}

	// Only include signinMethod and provider if they are explicitly selected in tokenFields
	if selectedFields["signinMethod"] {
		res["signinMethod"] = claims.SigninMethod
	}
	if selectedFields["provider"] {
		res["provider"] = claims.Provider
	}

	for _, field := range tokenField {
		if strings.HasPrefix(field, "Properties.") {
			/*
				Use selected properties fields as custom claims.
				Converts `Properties.my_field` to custom claim with name `my_field`.
			*/
			parts := strings.Split(field, ".")
			if len(parts) != 2 || parts[0] != "Properties" { // Either too many segments, or not properly scoped to `Properties`, so skip.
				continue
			}
			base, fieldName := parts[0], parts[1]
			mField := userValue.FieldByName(base)
			if !mField.IsValid() { // Can't find `Properties` field, so skip.
				continue
			}
			finalField := mField.MapIndex(reflect.ValueOf(fieldName))
			if finalField.IsValid() { // // Provided field within `Properties` exists, add claim.
				res[fieldName] = finalField.Interface()
			}

		} else if field == "permissionNames" {
			permissionNames := []string{}
			for _, val := range claims.User.Permissions {
				permissionNames = append(permissionNames, val.Name)
			}
			res[util.SnakeToCamel(util.CamelToSnakeCase(field))] = permissionNames
		} else { // Use selected user field as claims.
			userField := userValue.FieldByName(field)
			if userField.IsValid() {
				newfield := util.SnakeToCamel(util.CamelToSnakeCase(field))
				res[newfield] = userField.Interface()
			}
		}
	}

	for _, item := range tokenAttributes {
		var value interface{}

		// If Category is "Existing Field", get the actual field value from the user
		if item.Category == "Existing Field" {
			fieldValue, found := getUserFieldValue(claims.User, item.Value)
			if !found {
				continue
			}
			value = fieldValue
		} else {
			// Default behavior: use replaceAttributeValue for "Static Value" or empty category
			valueList := replaceAttributeValue(claims.User, item.Value)
			if len(valueList) == 0 {
				continue
			}

			if item.Type == "String" {
				value = valueList[0]
			} else {
				value = valueList
			}
		}

		res[item.Name] = value
	}

	return res
}

func refineUser(user *User) *User {
	user.Password = ""

	if user.Address == nil {
		user.Address = []string{}
	}
	if user.Properties == nil {
		user.Properties = map[string]string{}
	}
	if user.Roles == nil {
		user.Roles = []*Role{}
	}
	if user.Permissions == nil {
		user.Permissions = []*Permission{}
	}
	if user.Groups == nil {
		user.Groups = []string{}
	}

	return user
}

// tokenAudience decides the JWT `aud` claim — a pure decision decomplected from
// JWT assembly so it can be reasoned about and unit-tested in isolation:
//
//   - an explicit RFC 8707 `resource` wins: the caller names the resource
//     server the token is for (e.g. hanzo-console issuing a token for commerce
//     to consume — commerce's fixed audience allowlist then matches
//     deterministically, independent of WHICH app minted the token);
//   - otherwise a SHARED application gets a per-org audience
//     (`<clientId>-org-<owner>`) so one shared app's tokens stay org-scoped;
//   - otherwise the audience is the minting app's own clientId (the default,
//     unchanged for every existing login/OAuth flow).
//
// `userOwner` is the user's org slug, used only for the shared-app branch.
func tokenAudience(resource string, application *Application, userOwner string) []string {
	if resource != "" {
		return []string{resource}
	}
	if application.IsShared {
		return []string{application.ClientId + "-org-" + userOwner}
	}
	return []string{application.ClientId}
}

func generateJwtToken(application *Application, user *User, provider string, signinMethod string, nonce string, scope string, resource string, host string) (string, string, string, error) {
	nowTime := time.Now()
	expireTime := nowTime.Add(time.Duration(application.ExpireInHours * float64(time.Hour)))
	refreshExpireTime := nowTime.Add(time.Duration(application.RefreshExpireInHours * float64(time.Hour)))
	if application.RefreshExpireInHours == 0 {
		refreshExpireTime = expireTime
	}

	if conf.GetConfigBool("useGroupPathInToken") {
		groupPath, err := user.GetUserFullGroupPath()
		if err != nil {
			return "", "", "", err
		}

		user.Groups = groupPath
	}
	user = refineUser(user)

	// Canonical, brand-stable issuer (e.g. iam.hanzo.ai mints carry
	// iss=https://hanzo.id) so the gateway and cloud-api — which validate a
	// single fixed issuer per brand — accept every mint regardless of host.
	issuer := canonicalIssuer(host)

	name := util.GenerateId()
	jti := util.GetId(application.Owner, name)

	// Resolve the caller's org DEFAULT project for the `project` claim.
	// Best-effort and non-fatal: a lookup failure omits the claim (the gateway
	// then falls back to the default scope) rather than breaking token minting —
	// auth availability wins. Empty for guest/null users with no org.
	project := ""
	if defaultProject, err := GetDefaultProject(user.Owner); err != nil {
		logs.Warning("generateJwtToken: default project lookup for org %q failed: %v", user.Owner, err)
	} else if defaultProject != nil {
		project = defaultProject.Name
	}

	claims := Claims{
		User:      user,
		TokenType: "access-token",
		Nonce:     nonce,
		// FIXME: A workaround for custom claim by reusing `tag` in user info
		Tag:          user.Tag,
		Scope:        scope,
		Azp:          application.ClientId,
		Provider:     provider,
		Project:      project,
		SigninMethod: signinMethod,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.Id,
			Audience:  tokenAudience(resource, application, user.Owner),
			ExpiresAt: jwt.NewNumericDate(expireTime),
			NotBefore: jwt.NewNumericDate(nowTime),
			IssuedAt:  jwt.NewNumericDate(nowTime),
			ID:        jti,
		},
	}

	var token *jwt.Token
	var refreshToken *jwt.Token

	if application.TokenFormat == "" {
		application.TokenFormat = "JWT"
	}

	var jwtMethod jwt.SigningMethod

	switch application.TokenSigningMethod {
	case "RS256":
		jwtMethod = jwt.SigningMethodRS256
	case "RS512":
		jwtMethod = jwt.SigningMethodRS512
	case "ES256":
		jwtMethod = jwt.SigningMethodES256
	case "ES512":
		jwtMethod = jwt.SigningMethodES512
	case "ES384":
		jwtMethod = jwt.SigningMethodES384
	case algMLDSA65:
		jwtMethod = SigningMethodMLDSA65
	default:
		jwtMethod = jwt.SigningMethodRS256
	}

	// the JWT token length in "JWT-Empty" mode will be very short, as User object only has two properties: owner and name
	if application.TokenFormat == "JWT" {
		claimsWithoutThirdIdp := getClaimsWithoutThirdIdp(claims)

		token = jwt.NewWithClaims(jwtMethod, claimsWithoutThirdIdp)
		claimsWithoutThirdIdp.ExpiresAt = jwt.NewNumericDate(refreshExpireTime)
		claimsWithoutThirdIdp.TokenType = "refresh-token"
		refreshToken = jwt.NewWithClaims(jwtMethod, claimsWithoutThirdIdp)
	} else if application.TokenFormat == "JWT-Empty" {
		claimsShort := getShortClaims(claims)

		token = jwt.NewWithClaims(jwtMethod, claimsShort)
		claimsShort.ExpiresAt = jwt.NewNumericDate(refreshExpireTime)
		claimsShort.TokenType = "refresh-token"
		refreshToken = jwt.NewWithClaims(jwtMethod, claimsShort)
	} else if application.TokenFormat == "JWT-Custom" {
		claimsCustom := getClaimsCustom(claims, application.TokenFields, application.TokenAttributes)

		token = jwt.NewWithClaims(jwtMethod, claimsCustom)
		refreshClaims := getClaimsCustom(claims, application.TokenFields, application.TokenAttributes)
		refreshClaims["exp"] = jwt.NewNumericDate(refreshExpireTime)
		refreshClaims["TokenType"] = "refresh-token"
		refreshToken = jwt.NewWithClaims(jwtMethod, refreshClaims)
	} else if application.TokenFormat == "JWT-Standard" {
		claimsStandard := getStandardClaims(claims)

		token = jwt.NewWithClaims(jwtMethod, claimsStandard)
		claimsStandard.ExpiresAt = jwt.NewNumericDate(refreshExpireTime)
		claimsStandard.TokenType = "refresh-token"
		refreshToken = jwt.NewWithClaims(jwtMethod, claimsStandard)
	} else {
		return "", "", "", fmt.Errorf("unknown application TokenFormat: %s", application.TokenFormat)
	}

	cert, err := getCertByApplication(application)
	if err != nil {
		return "", "", "", err
	}

	if cert == nil {
		if application.Cert == "" {
			return "", "", "", fmt.Errorf("The cert field of the application \"%s\" should not be empty", application.GetId())
		} else {
			return "", "", "", fmt.Errorf("The cert \"%s\" does not exist", application.Cert)
		}
	}

	// Use cached parsed key to avoid PEM parsing on every token generation.
	key, err := parseCertPrivateKey(cert, application.TokenSigningMethod)
	if err != nil {
		return "", "", "", err
	}

	var tokenString, refreshTokenString string
	token.Header["kid"] = cert.Name
	tokenString, err = token.SignedString(key)
	if err != nil {
		return "", "", "", err
	}
	refreshTokenString, err = refreshToken.SignedString(key)

	return tokenString, refreshTokenString, name, err
}

func ParseJwtTokenWithoutValidation(token string) (*jwt.Token, error) {
	t, _, err := jwt.NewParser().ParseUnverified(token, &Claims{})
	if err != nil {
		return nil, err
	}

	return t, nil
}

func ParseJwtToken(token string, cert *Cert) (*Claims, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		var (
			certificate interface{}
			err         error
		)

		if cert.Certificate == "" {
			return nil, fmt.Errorf("the certificate field should not be empty for the cert: %v", cert)
		}

		if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			// RSA certificate
			certificate, err = jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
		} else if _, ok := token.Method.(*jwt.SigningMethodECDSA); ok {
			// ES certificate
			certificate, err = jwt.ParseECPublicKeyFromPEM([]byte(cert.Certificate))
		} else if _, ok := token.Method.(*signingMethodMLDSA65); ok {
			// ML-DSA-65 post-quantum key
			certificate, err = parseMLDSA65PublicKey(cert.Certificate)
		} else {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		if err != nil {
			return nil, err
		}

		return certificate, nil
	})

	if t != nil {
		if claims, ok := t.Claims.(*Claims); ok && t.Valid {
			return claims, nil
		}
	}

	return nil, err
}

func ParseJwtTokenByApplication(token string, application *Application) (*Claims, error) {
	cert, err := getCertByApplication(application)
	if err != nil {
		return nil, err
	}

	return ParseJwtToken(token, cert)
}

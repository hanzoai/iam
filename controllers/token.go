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

package controllers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hanzoai/beego/v2/core/utils/pagination"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// parseFormEncodedBody parses application/x-www-form-urlencoded data from the
// raw request body. This is needed because Beego's copyrequestbody=true reads
// the body into RequestBody, which can exhaust the io.Reader before Go's
// http.Request.ParseForm() runs. As a result, Input.Query() may not find
// form-encoded POST parameters. This helper provides a reliable fallback.
func parseFormEncodedBody(body []byte) url.Values {
	if len(body) == 0 {
		return nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil
	}
	return values
}

// getFormValue returns the value for a key from parsed form values, or empty string.
func getFormValue(values url.Values, key string) string {
	if values == nil {
		return ""
	}
	return values.Get(key)
}

// isFormEncoded checks if the request body looks like form-encoded data
// (contains & or = but does not start with {).
func isFormEncoded(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	s := strings.TrimSpace(string(body))
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return false
	}
	return strings.Contains(s, "=")
}

// GetTokens
// @Title GetTokens
// @Tag Token API
// @Description get tokens
// @Param   owner     query    string  true        "The organization name (e.g., admin)"
// @Param   pageSize     query    string  true        "The size of each page"
// @Param   p     query    string  true        "The number of the page"
// @Success 200 {array} object.Token The Response object
// @router /get-tokens [get]
func (c *ApiController) GetTokens() {
	owner := c.Ctx.Input.Query("owner")
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")
	organization := c.Ctx.Input.Query("organization")
	if limit == "" || page == "" {
		token, err := object.GetTokens(owner, organization)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(token)
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetTokenCount(owner, organization, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
		tokens, err := object.GetPaginationTokens(owner, organization, paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(tokens, paginator.Nums())
	}
}

// GetToken
// @Title GetToken
// @Tag Token API
// @Description get token
// @Param   id     query    string  true        "The token ID in format: organization/token-name (e.g., admin/token-123456)"
// @Success 200 {object} object.Token The Response object
// @router /get-token [get]
func (c *ApiController) GetToken() {
	id := c.Ctx.Input.Query("id")
	token, err := object.GetToken(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(token)
}

// UpdateToken
// @Title UpdateToken
// @Tag Token API
// @Description update token
// @Param   id     query    string  true        "The token ID in format: organization/token-name (e.g., admin/token-123456)"
// @Param   body    body   object.Token  true        "Details of the token"
// @Success 200 {object} controllers.Response The Response object
// @router /update-token [post]
func (c *ApiController) UpdateToken() {
	// Forging a Token row mints a bearer token out of band; gate app/<name>
	// mutation on IAM_TOKEN_ADMIN_APPS (empty/deny-all). Normal token issuance
	// via the OAuth grant endpoints is a different path and is unaffected.
	if !c.requireAppCapability(object.CapTokenAdmin) {
		return
	}

	id := c.Ctx.Input.Query("id")

	var token object.Token
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &token)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateToken(id, &token, c.IsGlobalAdmin()))
	c.ServeJSON()
}

// AddToken
// @Title AddToken
// @Tag Token API
// @Description add token
// @Param   body    body   object.Token  true        "Details of the token"
// @Success 200 {object} controllers.Response The Response object
// @router /add-token [post]
func (c *ApiController) AddToken() {
	if !c.requireAppCapability(object.CapTokenAdmin) {
		return
	}

	var token object.Token
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &token)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddToken(&token))
	c.ServeJSON()
}

// DeleteToken
// @Tag Token API
// @Title DeleteToken
// @Description delete token
// @Param   body    body   object.Token  true        "Details of the token"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-token [post]
func (c *ApiController) DeleteToken() {
	if !c.requireAppCapability(object.CapTokenAdmin) {
		return
	}

	var token object.Token
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &token)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteToken(&token))
	c.ServeJSON()
}

// GetOAuthToken
// @Title GetOAuthToken
// @Tag Token API
// @Description get OAuth access token
// @Param   grant_type     query    string  true        "OAuth grant type"
// @Param   client_id     query    string  true        "OAuth client id"
// @Param   client_secret     query    string  true        "OAuth client secret"
// @Param   code     query    string  true        "OAuth code"
// @Success 200 {object} object.TokenWrapper The Response object
// @Success 400 {object} object.TokenError The Response object
// @Success 401 {object} object.TokenError The Response object
// @router /v1/iam/oauth/access_token [post]
func (c *ApiController) GetOAuthToken() {
	clientId := c.Ctx.Input.Query("client_id")
	clientSecret := c.Ctx.Input.Query("client_secret")
	assertion := c.Ctx.Input.Query("assertion")
	clientAssertion := c.Ctx.Input.Query("client_assertion")
	clientAssertionType := c.Ctx.Input.Query("client_assertion_type")
	grantType := c.Ctx.Input.Query("grant_type")
	code := c.Ctx.Input.Query("code")
	verifier := c.Ctx.Input.Query("code_verifier")
	scope := c.Ctx.Input.Query("scope")
	nonce := c.Ctx.Input.Query("nonce")
	username := c.Ctx.Input.Query("username")
	password := c.Ctx.Input.Query("password")
	tag := c.Ctx.Input.Query("tag")
	avatar := c.Ctx.Input.Query("avatar")
	refreshToken := c.Ctx.Input.Query("refresh_token")
	deviceCode := c.Ctx.Input.Query("device_code")
	subjectToken := c.Ctx.Input.Query("subject_token")
	subjectTokenType := c.Ctx.Input.Query("subject_token_type")
	audience := c.Ctx.Input.Query("audience")
	resource := c.Ctx.Input.Query("resource")
	accessKey := c.Ctx.Input.Query("access_key")
	accessSecretKey := c.Ctx.Input.Query("access_secret")

	if clientId == "" && clientSecret == "" {
		clientId, clientSecret, _ = c.Ctx.Request.BasicAuth()
	}

	if len(c.Ctx.Input.RequestBody) != 0 && grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		// Try JSON first, then fall back to form-encoded parsing.
		// Beego's copyrequestbody=true can exhaust the request body reader,
		// causing Input.Query() to miss form-encoded POST parameters.
		var tokenRequest TokenRequest
		err := json.Unmarshal(c.Ctx.Input.RequestBody, &tokenRequest)
		if err == nil {
			if clientId == "" {
				clientId = tokenRequest.ClientId
			}
			if clientSecret == "" {
				clientSecret = tokenRequest.ClientSecret
			}
			if clientAssertion == "" {
				clientAssertion = tokenRequest.ClientAssertion
			}
			if clientAssertionType == "" {
				clientAssertionType = tokenRequest.ClientAssertionType
			}
			if grantType == "" {
				grantType = tokenRequest.GrantType
			}
			if code == "" {
				code = tokenRequest.Code
			}
			if verifier == "" {
				verifier = tokenRequest.Verifier
			}
			if scope == "" {
				scope = tokenRequest.Scope
			}
			if nonce == "" {
				nonce = tokenRequest.Nonce
			}
			if username == "" {
				username = tokenRequest.Username
			}
			if password == "" {
				password = tokenRequest.Password
			}
			if tag == "" {
				tag = tokenRequest.Tag
			}
			if avatar == "" {
				avatar = tokenRequest.Avatar
			}
			if refreshToken == "" {
				refreshToken = tokenRequest.RefreshToken
			}
			if subjectToken == "" {
				subjectToken = tokenRequest.SubjectToken
			}
			if subjectTokenType == "" {
				subjectTokenType = tokenRequest.SubjectTokenType
			}
			if audience == "" {
				audience = tokenRequest.Audience
			}
			if resource == "" {
				resource = tokenRequest.Resource
			}
			if assertion == "" {
				assertion = tokenRequest.Assertion
			}
			if accessKey == "" {
				accessKey = tokenRequest.AccessKey
			}
			if accessSecretKey == "" {
				accessSecretKey = tokenRequest.AccessSecretKey
			}
		} else if isFormEncoded(c.Ctx.Input.RequestBody) {
			// Fall back to parsing application/x-www-form-urlencoded body.
			// Standard OAuth 2.0 clients (e.g. NextAuth.js) send token requests
			// as form-encoded POST data, which Input.Query() may miss when
			// copyrequestbody=true exhausts the body reader.
			formValues := parseFormEncodedBody(c.Ctx.Input.RequestBody)
			if clientId == "" {
				clientId = getFormValue(formValues, "client_id")
			}
			if clientSecret == "" {
				clientSecret = getFormValue(formValues, "client_secret")
			}
			if clientAssertion == "" {
				clientAssertion = getFormValue(formValues, "client_assertion")
			}
			if clientAssertionType == "" {
				clientAssertionType = getFormValue(formValues, "client_assertion_type")
			}
			if grantType == "" {
				grantType = getFormValue(formValues, "grant_type")
			}
			if code == "" {
				code = getFormValue(formValues, "code")
			}
			if verifier == "" {
				verifier = getFormValue(formValues, "code_verifier")
			}
			if scope == "" {
				scope = getFormValue(formValues, "scope")
			}
			if nonce == "" {
				nonce = getFormValue(formValues, "nonce")
			}
			if username == "" {
				username = getFormValue(formValues, "username")
			}
			if password == "" {
				password = getFormValue(formValues, "password")
			}
			if tag == "" {
				tag = getFormValue(formValues, "tag")
			}
			if avatar == "" {
				avatar = getFormValue(formValues, "avatar")
			}
			if refreshToken == "" {
				refreshToken = getFormValue(formValues, "refresh_token")
			}
			if deviceCode == "" {
				deviceCode = getFormValue(formValues, "device_code")
			}
			if subjectToken == "" {
				subjectToken = getFormValue(formValues, "subject_token")
			}
			if subjectTokenType == "" {
				subjectTokenType = getFormValue(formValues, "subject_token_type")
			}
			if assertion == "" {
				assertion = getFormValue(formValues, "assertion")
			}
			if audience == "" {
				audience = getFormValue(formValues, "audience")
			}
			if resource == "" {
				resource = getFormValue(formValues, "resource")
			}
			if accessKey == "" {
				accessKey = getFormValue(formValues, "access_key")
			}
			if accessSecretKey == "" {
				accessSecretKey = getFormValue(formValues, "access_secret")
			}
		}
	}

	host := c.getEffectiveHost()

	// Device Authorization Grant (RFC 8628) is handled self-contained: identity
	// comes ONLY from the approved device-auth cache (keyed by device_code),
	// never from a request `username`, and the generic token path refuses it.
	if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
		c.handleDeviceCodeToken(deviceCode, clientId, nonce, host)
		return
	}

	token, err := object.GetOAuthToken(grantType, clientId, clientSecret, code, verifier, scope, nonce, username, password, host, refreshToken, tag, avatar, c.GetAcceptLanguage(), subjectToken, subjectTokenType, assertion, clientAssertion, clientAssertionType, audience, resource, accessKey, accessSecretKey)
	if err != nil {
		c.ResponseTokenError("server_error", err.Error())
		return
	}

	c.Data["json"] = token
	c.SetTokenErrorHttpStatus()
	c.ServeJSON()
}

// handleDeviceCodeToken redeems an approved device authorization (RFC 8628) for
// a token. The approving user's identity is taken SOLELY from the device-auth
// cache entry keyed by deviceCode — never from a request `username` — so a
// missing/unknown device_code, or one not yet approved, can never yield a token.
// The approved entry is consumed atomically (LoadAndDelete) so one approval
// issues at most one token even under concurrent polls.
func (c *ApiController) handleDeviceCodeToken(deviceCode string, clientId string, nonce string, host string) {
	if deviceCode == "" {
		c.Data["json"] = &object.TokenError{
			Error:            "invalid_request",
			ErrorDescription: "device_code is required",
		}
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}

	cached, ok := object.DeviceAuthMap.Load(deviceCode)
	if !ok {
		c.Data["json"] = &object.TokenError{
			Error:            "expired_token",
			ErrorDescription: "token is expired",
		}
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}
	deviceAuth := cached.(object.DeviceAuthCache)

	if !deviceAuth.UserSignIn {
		// Not approved yet — leave the entry in place so the client keeps polling.
		c.Data["json"] = &object.TokenError{
			Error:            "authorization_pending",
			ErrorDescription: "authorization pending",
		}
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}

	if deviceAuth.RequestAt.Add(time.Second * object.DeviceCodeExpirySeconds).Before(time.Now()) {
		object.DeviceAuthMap.Delete(deviceCode)
		c.Data["json"] = &object.TokenError{
			Error:            "expired_token",
			ErrorDescription: "token is expired",
		}
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}

	// Approved: consume the code atomically. Only the goroutine that wins the
	// delete issues a token, so a single approval can never mint two tokens.
	if _, consumed := object.DeviceAuthMap.LoadAndDelete(deviceCode); !consumed {
		c.Data["json"] = &object.TokenError{
			Error:            "expired_token",
			ErrorDescription: "token is expired",
		}
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}

	application, err := object.GetApplicationByClientId(clientId)
	if err != nil {
		c.ResponseTokenError("server_error", err.Error())
		return
	}
	if application == nil {
		c.Data["json"] = &object.TokenError{
			Error:            "invalid_client",
			ErrorDescription: "client_id is invalid",
		}
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}

	tokenWrapper, tokenError, err := object.GetDeviceCodeToken(application, &deviceAuth, nonce, host)
	if err != nil {
		c.ResponseTokenError("server_error", err.Error())
		return
	}
	if tokenError != nil {
		c.Data["json"] = tokenError
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}

	// *TokenWrapper → SetTokenErrorHttpStatus emits 200 + no-store (RFC 6749 §5.1).
	c.Data["json"] = tokenWrapper
	c.SetTokenErrorHttpStatus()
	c.ServeJSON()
}

// RefreshToken
// @Title RefreshToken
// @Tag Token API
// @Description refresh OAuth access token
// @Param   grant_type     query    string  true        "OAuth grant type"
// @Param	refresh_token	query	string	true		"OAuth refresh token"
// @Param   scope     query    string  true        "OAuth scope"
// @Param   client_id     query    string  true        "OAuth client id"
// @Param   client_secret     query    string  false        "OAuth client secret"
// @Success 200 {object} object.TokenWrapper The Response object
// @Success 400 {object} object.TokenError The Response object
// @Success 401 {object} object.TokenError The Response object
// @router /v1/iam/oauth/refresh_token [post]
func (c *ApiController) RefreshToken() {
	grantType := c.Ctx.Input.Query("grant_type")
	refreshToken := c.Ctx.Input.Query("refresh_token")
	scope := c.Ctx.Input.Query("scope")
	clientId := c.Ctx.Input.Query("client_id")
	clientSecret := c.Ctx.Input.Query("client_secret")
	host := c.getEffectiveHost()

	if clientId == "" && clientSecret == "" {
		clientId, clientSecret, _ = c.Ctx.Request.BasicAuth()
	}

	if clientId == "" {
		// Try JSON first, then fall back to form-encoded parsing.
		var tokenRequest TokenRequest
		if err := json.Unmarshal(c.Ctx.Input.RequestBody, &tokenRequest); err == nil {
			clientId = tokenRequest.ClientId
			clientSecret = tokenRequest.ClientSecret
			grantType = tokenRequest.GrantType
			scope = tokenRequest.Scope
			refreshToken = tokenRequest.RefreshToken
		} else if isFormEncoded(c.Ctx.Input.RequestBody) {
			formValues := parseFormEncodedBody(c.Ctx.Input.RequestBody)
			if clientId == "" {
				clientId = getFormValue(formValues, "client_id")
			}
			if clientSecret == "" {
				clientSecret = getFormValue(formValues, "client_secret")
			}
			if grantType == "" {
				grantType = getFormValue(formValues, "grant_type")
			}
			if scope == "" {
				scope = getFormValue(formValues, "scope")
			}
			if refreshToken == "" {
				refreshToken = getFormValue(formValues, "refresh_token")
			}
		}
	}

	ok, application, clientId, _, err := c.ValidateOAuth(true)
	if err != nil || !ok {
		return
	}

	refreshToken2, err := object.RefreshToken(application, grantType, refreshToken, scope, clientId, clientSecret, host)
	if err != nil {
		c.ResponseTokenError("server_error", err.Error())
		return
	}

	c.Data["json"] = refreshToken2
	c.SetTokenErrorHttpStatus()
	c.ServeJSON()
}

func (c *ApiController) ResponseTokenError(errorMsg string, errorDescription string) {
	c.Data["json"] = &object.TokenError{
		Error:            errorMsg,
		ErrorDescription: errorDescription,
	}
	c.SetTokenErrorHttpStatus()
	c.ServeJSON()
}

func (c *ApiController) ValidateOAuth(ignoreValidSecret bool) (ok bool, application *object.Application, clientId, clientSecret string, err error) {
	reqClientId := c.Ctx.Input.Query("client_id")
	reqClientSecret := c.Ctx.Input.Query("client_secret")
	clientAssertion := c.Ctx.Input.Query("client_assertion")
	clientAssertionType := c.Ctx.Input.Query("client_assertion_type")

	if reqClientId == "" && clientAssertionType == "" {
		var tokenRequest TokenRequest
		if err := json.Unmarshal(c.Ctx.Input.RequestBody, &tokenRequest); err == nil {
			reqClientId = tokenRequest.ClientId
			reqClientSecret = tokenRequest.ClientSecret
			clientAssertion = tokenRequest.ClientAssertion
			clientAssertionType = tokenRequest.ClientAssertionType
		} else if isFormEncoded(c.Ctx.Input.RequestBody) {
			formValues := parseFormEncodedBody(c.Ctx.Input.RequestBody)
			reqClientId = getFormValue(formValues, "client_id")
			reqClientSecret = getFormValue(formValues, "client_secret")
			clientAssertion = getFormValue(formValues, "client_assertion")
			clientAssertionType = getFormValue(formValues, "client_assertion_type")
		}
	}

	if clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		ok, application, err = object.ValidateClientAssertion(clientAssertion, c.getEffectiveHost())
		if err != nil {
			c.ResponseTokenError(object.InvalidClient, err.Error())
			return
		}

		if !ok || application == nil {
			c.ResponseTokenError(object.InvalidClient, "client_assertion is invalid")
			return
		}

		clientSecret = application.ClientSecret
		clientId = application.ClientId
		ok = true
		return
	}

	if reqClientId == "" && reqClientSecret == "" {
		clientId, clientSecret, ok = c.Ctx.Request.BasicAuth()
		if !ok {
			clientId = c.Ctx.Input.Query("client_id")
			clientSecret = c.Ctx.Input.Query("client_secret")
			if clientId == "" || clientSecret == "" {
				c.ResponseTokenError(object.InvalidRequest, "")
				return
			}
		}
	} else {
		clientId = reqClientId
		clientSecret = reqClientSecret
	}

	application, err = object.GetApplicationByClientId(clientId)
	if err != nil {
		c.ResponseTokenError(object.InvalidClient, err.Error())
		return
	}

	if application == nil || (application.ClientSecret != clientSecret && !ignoreValidSecret) {
		c.ResponseTokenError(object.InvalidClient, c.T("token:Invalid application or wrong clientSecret"))
		return
	}

	ok = true
	return
}

// RevokeToken
// @Title RevokeToken
// @Tag Token API
// @Description Revoke an OAuth 2.0 token (access_token or refresh_token).
// Implements RFC 7009 - OAuth 2.0 Token Revocation.
// This endpoint supports both Basic Authorization, JWT client assertion (RFC 7523),
// and form-encoded client credentials.
//
// @Param token formData string true "The token to revoke"
// @Param token_type_hint formData string false "Hint about the token type: access_token or refresh_token"
// @Param client_id formData string false "OAuth client ID (if not using Basic Auth)"
// @Param client_secret formData string false "OAuth client secret (if not using Basic Auth)"
// @Success 200 {object} object.Response Success (RFC 7009 requires 200 even for invalid tokens)
// @Success 401 {object} object.TokenError Invalid client credentials
// @router /v1/iam/oauth/revoke [post]
func (c *ApiController) RevokeToken() {
	tokenValue := c.Ctx.Input.Query("token")
	tokenTypeHint := c.Ctx.Input.Query("token_type_hint")

	ok, _, clientId, _, err := c.ValidateOAuth(false)
	if err != nil || !ok {
		return
	}

	// Fall back to form-encoded body parsing for token value
	if tokenValue == "" && isFormEncoded(c.Ctx.Input.RequestBody) {
		formValues := parseFormEncodedBody(c.Ctx.Input.RequestBody)
		if tokenValue == "" {
			tokenValue = getFormValue(formValues, "token")
		}
		if tokenTypeHint == "" {
			tokenTypeHint = getFormValue(formValues, "token_type_hint")
		}
	}

	// RFC 7009: If the token is empty, respond with success
	if tokenValue == "" {
		c.ResponseOk()
		return
	}

	// Try to find the token by the hint, or try both types
	var token *object.Token
	var foundTokenType string

	if tokenTypeHint == "refresh_token" || tokenTypeHint == "refresh-token" {
		token, err = object.GetTokenByRefreshToken(tokenValue)
		foundTokenType = "refresh_token"
	} else {
		// Default to access_token, but try both
		token, err = object.GetTokenByAccessToken(tokenValue)
		foundTokenType = "access_token"
		if err == nil && token == nil {
			token, err = object.GetTokenByRefreshToken(tokenValue)
			foundTokenType = "refresh_token"
		}
	}

	if err != nil {
		// RFC 7009: Return success even on errors to prevent token scanning
		c.ResponseOk()
		return
	}

	// RFC 7009: The authorization server responds with HTTP 200 even if the
	// token was invalid or already revoked
	if token == nil {
		c.ResponseOk()
		return
	}

	// Calculate expiration time
	createdTime, _ := time.Parse(time.RFC3339, token.CreatedTime)
	expiresAt := createdTime.Add(time.Duration(token.ExpiresIn) * time.Second)

	// Revoke the token
	err = object.RevokeToken(
		tokenValue,
		foundTokenType,
		"", // revokedBy - could be extracted from client ID
		clientId,
		token.Owner,
		token.Application,
		expiresAt,
	)
	if err != nil {
		// Log the error but still return success per RFC 7009
		c.ResponseOk()
		return
	}

	// Also delete the token from the active tokens table
	_, _ = object.DeleteToken(token)

	c.ResponseOk()
}

// IntrospectToken
// @Title IntrospectToken
// @Tag Login API
// @Description The introspection endpoint is an OAuth 2.0 endpoint that takes a
// parameter representing an OAuth 2.0 token and returns a JSON document
// representing the meta information surrounding the
// token, including whether this token is currently active.
// This endpoint support Basic Authorization and authorization defined in RFC 7523.
//
// @Param token formData string true "access_token's value or refresh_token's value"
// @Param token_type_hint formData string true "the token type access_token or refresh_token"
// @Success 200 {object} object.IntrospectionResponse The Response object
// @Success 400 {object} object.TokenError The Response object
// @Success 401 {object} object.TokenError The Response object
// @router /v1/iam/oauth/introspect [post]
func (c *ApiController) IntrospectToken() {
	tokenValue := c.Ctx.Input.Query("token")

	// Fall back to form-encoded body parsing for the token value
	if tokenValue == "" && isFormEncoded(c.Ctx.Input.RequestBody) {
		formValues := parseFormEncodedBody(c.Ctx.Input.RequestBody)
		tokenValue = getFormValue(formValues, "token")
	}

	ok, application, clientId, _, err := c.ValidateOAuth(false)
	if err != nil || !ok {
		return
	}

	respondWithInactiveToken := func() {
		c.Data["json"] = &object.IntrospectionResponse{Active: false}
		c.ServeJSON()
	}

	tokenTypeHint := c.Ctx.Input.Query("token_type_hint")
	if tokenTypeHint == "" && isFormEncoded(c.Ctx.Input.RequestBody) {
		formValues := parseFormEncodedBody(c.Ctx.Input.RequestBody)
		tokenTypeHint = getFormValue(formValues, "token_type_hint")
	}
	var token *object.Token
	if tokenTypeHint != "" {
		token, err = object.GetTokenByTokenValue(tokenValue, tokenTypeHint)
		if err != nil {
			c.ResponseTokenError(object.InvalidRequest, err.Error())
			return
		}
		if token == nil || token.ExpiresIn <= 0 {
			respondWithInactiveToken()
			return
		}

		if token.ExpiresIn <= 0 {
			c.Data["json"] = &object.IntrospectionResponse{Active: false}
			c.ServeJSON()
			return
		}
	}

	var introspectionResponse object.IntrospectionResponse

	// Check if token has been revoked (RFC 7009)
	revoked, err := object.IsTokenRevoked(tokenValue)
	if err != nil {
		c.ResponseTokenError(object.InvalidRequest, err.Error())
		return
	}
	if revoked {
		respondWithInactiveToken()
		return
	}

	if application.TokenFormat == "JWT-Standard" {
		jwtToken, err := object.ParseStandardJwtTokenByApplication(tokenValue, application)
		if err != nil {
			respondWithInactiveToken()
			return
		}

		introspectionResponse = object.IntrospectionResponse{
			Active:    true,
			Scope:     jwtToken.Scope,
			ClientId:  clientId,
			Username:  jwtToken.Name,
			TokenType: jwtToken.TokenType,
			Exp:       jwtToken.ExpiresAt.Unix(),
			Iat:       jwtToken.IssuedAt.Unix(),
			Nbf:       jwtToken.NotBefore.Unix(),
			Sub:       jwtToken.Subject,
			Aud:       jwtToken.Audience,
			Iss:       jwtToken.Issuer,
			Jti:       jwtToken.ID,
		}
	} else {
		jwtToken, err := object.ParseJwtTokenByApplication(tokenValue, application)
		if err != nil {
			respondWithInactiveToken()
			return
		}

		introspectionResponse = object.IntrospectionResponse{
			Active:   true,
			ClientId: clientId,
			Exp:      jwtToken.ExpiresAt.Unix(),
			Iat:      jwtToken.IssuedAt.Unix(),
			Nbf:      jwtToken.NotBefore.Unix(),
			Sub:      jwtToken.Subject,
			Aud:      jwtToken.Audience,
			Iss:      jwtToken.Issuer,
			Jti:      jwtToken.ID,
		}

		if jwtToken.Scope != "" {
			introspectionResponse.Scope = jwtToken.Scope
		}
		if jwtToken.Name != "" {
			introspectionResponse.Username = jwtToken.Name
		}
		if jwtToken.TokenType != "" {
			introspectionResponse.TokenType = jwtToken.TokenType
		}
	}

	if tokenTypeHint == "" {
		token, err = object.GetTokenByTokenValue(tokenValue, introspectionResponse.TokenType)
		if err != nil {
			c.ResponseTokenError(object.InvalidRequest, err.Error())
			return
		}
		if token == nil || token.ExpiresIn <= 0 {
			respondWithInactiveToken()
			return
		}
	}

	if token != nil {
		application, err = object.GetApplication(fmt.Sprintf("%s/%s", token.Owner, token.Application))
		if err != nil {
			c.ResponseTokenError(object.InvalidClient, err.Error())
			return
		}
		if application == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), token.Application))
			return
		}

		introspectionResponse.TokenType = token.TokenType
		introspectionResponse.ClientId = application.ClientId
	}

	c.Data["json"] = introspectionResponse
	c.ServeJSON()
}

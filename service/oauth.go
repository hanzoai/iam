// Copyright 2023 The Hanzo Authors. All Rights Reserved.
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

package service

import (
	"fmt"
	"net/http"
	"net/url"

	iamsdk "github.com/hanzoai/iamsdk/v2/iamsdk"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

func getSigninUrl(iamClient *iamsdk.Client, callbackUrl string, originalPath string) string {
	scope := "read"
	return fmt.Sprintf("%s/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=%s&state=%s",
		iamClient.Endpoint, iamClient.ClientId, url.QueryEscape(callbackUrl), scope, url.QueryEscape(originalPath))
}

func redirectToIAM(iamClient *iamsdk.Client, w http.ResponseWriter, r *http.Request) {
	scheme := getScheme(r)

	callbackUrl := fmt.Sprintf("%s://%s/waf-handler", scheme, r.Host)
	originalPath := r.RequestURI
	signinUrl := getSigninUrl(iamClient, callbackUrl, originalPath)
	http.Redirect(w, r, signinUrl, http.StatusFound)
}

func handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	site := getSiteByDomainWithWww(r.Host)
	if site == nil {
		responseError(w, "IAM WAF error: site not found for host: %s", r.Host)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" {
		responseError(w, "IAM WAF error: the code should not be empty")
		return
	} else if state == "" {
		responseError(w, "IAM WAF error: the state should not be empty")
		return
	}

	application, err := object.GetApplication(util.GetId(site.Owner, site.IamApplication))
	if err != nil {
		responseError(w, "IAM WAF error: iamClient.GetOAuthToken() error: %s", err.Error())
		return
	}

	//iamClient, err := getIAMClientFromSite(site)
	//if err != nil {
	//	responseError(w, "IAM WAF error: getIAMClientFromSite() error: %s", err.Error())
	//	return
	//}

	token, tokenError, err := object.GetAuthorizationCodeToken(application, application.ClientSecret, code, "", "")
	if tokenError != nil {
		responseError(w, "IAM WAF error: iamClient.GetOAuthToken() error: %s", tokenError.Error)
		return
	}
	if err != nil {
		responseError(w, "IAM WAF error: iamClient.GetOAuthToken() error: %s", err.Error())
		return
	}

	cookie := &http.Cookie{
		Name:  "iam_access_token",
		Value: token.AccessToken,
		Path:  "/",
	}
	http.SetCookie(w, cookie)

	originalPath := state
	http.Redirect(w, r, originalPath, http.StatusFound)
}

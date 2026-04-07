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

// @ts-nocheck
import React, {Suspense, lazy, useCallback, useEffect, useRef, useState} from "react";
import {Form, Input, Checkbox, Col, Tabs, message} from "antd";
import {withRouter} from "react-router-dom";
import {LogIn, Eye, EyeOff, Mail, Lock, User, Phone, ArrowLeft, Loader2} from "lucide-react";
import * as UserWebauthnBackend from "../backend/UserWebauthnBackend";
import OrganizationSelect from "../common/select/OrganizationSelect";
import * as Conf from "../Conf";
import * as Obfuscator from "./Obfuscator";
import * as AuthBackend from "./AuthBackend";
import * as OrganizationBackend from "../backend/OrganizationBackend";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as Provider from "./Provider";
import * as Util from "./Util";
import * as Setting from "../Setting";
import * as AgreementModal from "../common/modal/AgreementModal";
import SelfLoginButton from "./SelfLoginButton";
import i18next from "i18next";
import {SendCodeInput} from "../common/SendCodeInput";
import LanguageSelect from "../common/select/LanguageSelect";
import {CaptchaModal, CaptchaRule} from "../common/modal/CaptchaModal";
import RedirectForm from "../common/RedirectForm";
import {RequiredMfa} from "./mfa/MfaAuthVerifyForm";
import {GoogleOneTapLoginVirtualButton} from "./GoogleLoginButton";
import * as ProviderButton from "./ProviderButton";
import {createFormAndSubmit, goToLink} from "../Setting";
import WeChatLoginPanel from "./WeChatLoginPanel";
import {CountryCodeSelect} from "../common/select/CountryCodeSelect";
const FaceRecognitionCommonModal = lazy(() => import("../common/modal/FaceRecognitionCommonModal"));
const FaceRecognitionModal = lazy(() => import("../common/modal/FaceRecognitionModal"));

function LoginPage(props) {
  const captchaRef = useRef(null);
  const formRef = useRef(null);
  const urlParams = new URLSearchParams(props.location?.search);

  const [type] = useState(props.type);
  const [applicationName, setApplicationName] = useState(props.applicationName ?? (props.match?.params?.applicationName ?? null));
  const [owner] = useState(props.owner ?? (props.match?.params?.owner ?? null));
  const [mode] = useState(props.mode ?? (props.match?.params?.mode ?? null));
  const [msg, setMsg] = useState(null);
  const [username, setUsername] = useState(null);
  const [validEmailOrPhone, setValidEmailOrPhone] = useState(false);
  const [validEmail, setValidEmail] = useState(false);
  const [openCaptchaModal, setOpenCaptchaModal] = useState(false);
  const [openFaceRecognitionModal, setOpenFaceRecognitionModal] = useState(false);
  const [captchaValues, setCaptchaValues] = useState(undefined);
  const [samlResponse, setSamlResponse] = useState("");
  const [relayState, setRelayState] = useState("");
  const [redirectUrl, setRedirectUrl] = useState("");
  const [orgChoiceMode, setOrgChoiceMode] = useState(new URLSearchParams(props.location?.search).get("orgChoiceMode") ?? null);
  const [userLang, setUserLang] = useState(null);
  const [loginLoading, setLoginLoading] = useState(false);
  const [userCode] = useState(props.userCode ?? (props.match?.params?.userCode ?? null));
  const [userCodeStatus, setUserCodeStatus] = useState("");
  const [prefilledUsername] = useState(urlParams.get("username") || urlParams.get("login_hint"));
  const [loginMethod, setLoginMethod] = useState(undefined);
  const [haveFaceIdProvider, setHaveFaceIdProvider] = useState(false);
  const [values, setValues] = useState(null);
  const [getVerifyTotp, setGetVerifyTotp] = useState(undefined);
  const [mfaProps, setMfaProps] = useState(undefined);
  const [selectedMfaProp, setSelectedMfaProp] = useState(undefined);
  const [passwordVisible, setPasswordVisible] = useState(false);

  // Create a class-component-like wrapper for checkLoginMfa compatibility
  const getComponentThis = useCallback(() => ({
    props,
    state: {loginMethod, getVerifyTotp, mfaProps, selectedMfaProp},
    setState: (newState, callback) => {
      if (newState.mfaProps !== undefined) {setMfaProps(newState.mfaProps);}
      if (newState.selectedMfaProp !== undefined) {setSelectedMfaProp(newState.selectedMfaProp);}
      if (newState.getVerifyTotp !== undefined) {setGetVerifyTotp(() => newState.getVerifyTotp);}
      if (callback) {
        // Use setTimeout to ensure state is updated before callback runs
        setTimeout(callback, 0);
      }
    },
  }), [props, loginMethod, getVerifyTotp, mfaProps, selectedMfaProp]);

  // Store CAS type state
  const ownerRef = useRef(owner);
  if (type === "cas" && props.match?.params.casApplicationName !== undefined) {
    ownerRef.current = props.match?.params?.owner;
  }

  localStorage.setItem("signinUrl", window.location.pathname + window.location.search);

  const getApplicationObj = useCallback(() => {
    return props.application;
  }, [props.application]);

  const onUpdateAccount = useCallback((account) => {
    props.onUpdateAccount(account);
  }, [props.onUpdateAccount]);

  const onUpdateApplication = useCallback((application) => {
    props.onUpdateApplication(application);
    if (application === null) {
      return;
    }
    for (const idx in application.providers) {
      const provider = application.providers[idx];
      if (provider.provider?.category === "Face ID") {
        setHaveFaceIdProvider(true);
        break;
      }
    }
  }, [props.onUpdateApplication]);

  const refreshInlineCaptcha = useCallback(() => {
    captchaRef.current?.loadCaptcha?.();
  }, []);

  const isInlineCaptchaEnabled = useCallback((application = getApplicationObj()) => {
    return application?.signinItems?.some(signinItem => signinItem.name === "Captcha" && signinItem.rule === "inline");
  }, [getApplicationObj]);

  const getDefaultLoginMethod = useCallback((application) => {
    if (application?.signinMethods?.length > 0) {
      switch (application?.signinMethods[0].name) {
      case "Password": return "password";
      case "Verification code": {
        switch (application?.signinMethods[0].rule) {
        case "All": return "verificationCode";
        case "Email only": return "verificationCodeEmail";
        case "Phone only": return "verificationCodePhone";
        }
        break;
      }
      case "WebAuthn": return "webAuthn";
      case "LDAP": return "ldap";
      case "Face ID": return "faceId";
      }
    }
    return "password";
  }, []);

  const getCurrentLoginMethod = useCallback(() => {
    if (loginMethod === "password") {
      return "Password";
    } else if (loginMethod?.includes("verificationCode")) {
      return "Verification code";
    } else if (loginMethod === "webAuthn") {
      return "WebAuthn";
    } else if (loginMethod === "ldap") {
      return "LDAP";
    } else if (loginMethod === "faceId") {
      return "Face ID";
    } else {
      return "Password";
    }
  }, [loginMethod]);

  const getPlaceholder = useCallback((defaultPlaceholder = null) => {
    if (defaultPlaceholder) {
      return defaultPlaceholder;
    }
    switch (loginMethod) {
    case "verificationCode": return i18next.t("login:Email or phone");
    case "verificationCodeEmail": return i18next.t("general:Email");
    case "verificationCodePhone": return i18next.t("general:Phone");
    case "ldap": return i18next.t("login:LDAP username, Email or phone");
    default: return i18next.t("login:username, Email or phone");
    }
  }, [loginMethod]);

  const parseOffset = useCallback((offset) => {
    if (offset === 2 || offset === 4 || Setting.inIframe() || Setting.isMobile()) {
      return "0 auto";
    }
    if (offset === 1) {
      return "0 10%";
    }
    if (offset === 3) {
      return "0 60%";
    }
  }, []);

  const populateOauthValues = useCallback((vals) => {
    if (getApplicationObj()?.organization) {
      vals["organization"] = getApplicationObj().organization;
    }
    vals["signinMethod"] = getCurrentLoginMethod();
    const oAuthParams = Util.getOAuthGetParameters();
    vals["type"] = oAuthParams?.responseType ?? type;
    if (userCode) {
      vals["userCode"] = userCode;
    }
    if (oAuthParams?.samlRequest) {
      vals["samlRequest"] = oAuthParams.samlRequest;
      vals["type"] = "saml";
      vals["relayState"] = oAuthParams.relayState;
    }
  }, [getApplicationObj, getCurrentLoginMethod, type, userCode]);

  const sendPopupData = useCallback((message, redirectUri) => {
    const params = new URLSearchParams(props.location.search);
    if (params.get("popup") === "1") {
      window.opener.postMessage(message, redirectUri);
    }
  }, [props.location.search]);

  const sendSilentSigninData = useCallback((data) => {
    if (Setting.inIframe()) {
      const msg = {tag: "Hanzo IAM", type: "SilentSignin", data: data};
      window.parent.postMessage(msg, "*");
    }
  }, []);

  const getCaptchaProviderItems = useCallback((application) => {
    const providers = application?.providers;
    if (providers === undefined || providers === null) {
      return null;
    }
    return providers.filter(providerItem => {
      if (providerItem.provider === undefined || providerItem.provider === null) {
        return false;
      }
      return providerItem.provider.category === "Captcha";
    });
  }, []);

  const getCaptchaRule = useCallback((application) => {
    const captchaProviderItems = getCaptchaProviderItems(application);
    if (captchaProviderItems) {
      if (captchaProviderItems.some(providerItem => providerItem.rule === "Always")) {
        return CaptchaRule.Always;
      } else if (captchaProviderItems.some(providerItem => providerItem.rule === "Dynamic")) {
        return CaptchaRule.Dynamic;
      } else if (captchaProviderItems.some(providerItem => providerItem.rule === "Internet-Only")) {
        return CaptchaRule.InternetOnly;
      } else {
        return CaptchaRule.Never;
      }
    }
  }, [getCaptchaProviderItems]);

  const postCodeLoginAction = useCallback((resp) => {
    const application = getApplicationObj();
    const oAuthParams = Util.getOAuthGetParameters();
    const code = resp.data;
    const concatChar = oAuthParams?.redirectUri?.includes("?") ? "&" : "?";
    const noRedirect = oAuthParams.noRedirect;
    const redirectUrl = `${oAuthParams.redirectUri}${concatChar}code=${code}&state=${oAuthParams.state}`;
    if (resp.data === RequiredMfa) {
      props.onLoginSuccess(window.location.href);
      return;
    }

    if (resp.data3) {
      sessionStorage.setItem("signinUrl", window.location.pathname + window.location.search);
      Setting.goToLinkSoft({props}, "/account");
      return;
    }

    if (resp.data?.required === true) {
      Setting.goToLinkSoft({props}, `/consent/${application.name}?${window.location.search.substring(1)}`);
      return;
    }

    if (Setting.hasPromptPage(application)) {
      AuthBackend.getAccount()
        .then((res) => {
          if (res.status === "ok") {
            const account = res.data;
            account.organization = res.data2;
            onUpdateAccount(account);

            if (Setting.isPromptAnswered(account, application)) {
              Setting.goToLink(redirectUrl);
            } else {
              Setting.goToLinkSoft({props}, `/prompt/${application.name}?redirectUri=${oAuthParams.redirectUri}&code=${code}&state=${oAuthParams.state}`);
            }
          } else {
            Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
          }
        });
    } else {
      if (noRedirect === "true") {
        window.close();
        const newWindow = window.open(redirectUrl);
        if (newWindow) {
          setInterval(() => {
            if (!newWindow.closed) {
              newWindow.close();
            }
          }, 1000);
        }
      } else {
        Setting.goToLink(redirectUrl);
        sendPopupData({type: "loginSuccess", data: {code: code, state: oAuthParams.state}}, oAuthParams.redirectUri);
      }
    }
  }, [getApplicationObj, onUpdateAccount, props, sendPopupData]);

  const login = useCallback((vals) => {
    vals["language"] = userLang ?? "";
    const usedCaptcha = captchaValues !== undefined;
    const inlineCaptchaEnabled = isInlineCaptchaEnabled();
    const shouldRefreshCaptcha = usedCaptcha && inlineCaptchaEnabled && !loginMethod?.includes("verificationCode");
    if (type === "cas") {
      const casParams = Util.getCasParameters();
      vals["signinMethod"] = getCurrentLoginMethod();
      vals["type"] = type;
      AuthBackend.loginCas(vals, casParams).then((res) => {
        const loginHandler = (res) => {
          let msg = "Logged in successfully. ";
          if (casParams.service === "") {
            msg += "Now you can visit apps protected by IAM.";
          }
          Setting.showMessage("success", msg);

          if (casParams.service !== "") {
            const st = res.data;
            const newUrl = new URL(casParams.service);
            newUrl.searchParams.append("ticket", st);
            window.location.href = newUrl.toString();
          }
        };

        if (res.status === "ok") {
          Setting.checkLoginMfa(res, vals, casParams, loginHandler, getComponentThis());
        } else {
          Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
          if (shouldRefreshCaptcha) {
            refreshInlineCaptcha();
          }
        }
      }).finally(() => {
        setLoginLoading(false);
      });
    } else {
      const oAuthParams = Util.getOAuthGetParameters();
      populateOauthValues(vals);
      AuthBackend.login(vals, oAuthParams)
        .then((res) => {
          const loginHandler = (res) => {
            const responseType = vals["type"];
            const responseTypes = responseType.split(" ");
            const responseMode = oAuthParams?.responseMode || "query";
            if (responseType === "login") {
              if (res.data3) {
                sessionStorage.setItem("signinUrl", window.location.pathname + window.location.search);
                Setting.goToLinkSoft({props}, "/account");
                return;
              }
              Setting.showMessage("success", i18next.t("application:Logged in successfully"));
              props.onLoginSuccess();
            } else if (responseType === "code") {
              postCodeLoginAction(res);
            } else if (responseType === "device") {
              Setting.showMessage("success", "Successful login");
              setUserCodeStatus("success");
            } else if (responseTypes.includes("token") || responseTypes.includes("id_token")) {
              if (res.data3) {
                sessionStorage.setItem("signinUrl", window.location.pathname + window.location.search);
                Setting.goToLinkSoft({props}, "/account");
                return;
              }
              const amendatoryResponseType = responseType === "token" ? "access_token" : responseType;
              const accessToken = res.data;
              if (responseMode === "form_post") {
                const params = {
                  token: responseTypes.includes("token") ? res.data : null,
                  id_token: responseTypes.includes("id_token") ? res.data : null,
                  token_type: "bearer",
                  state: oAuthParams?.state,
                };
                createFormAndSubmit(oAuthParams?.redirectUri, params);
              } else {
                Setting.goToLink(`${oAuthParams.redirectUri}#${amendatoryResponseType}=${accessToken}&state=${oAuthParams.state}&token_type=bearer`);
              }
            } else if (responseType === "saml") {
              if (res.data === RequiredMfa) {
                props.onLoginSuccess(window.location.href);
                return;
              }
              if (res.data3) {
                sessionStorage.setItem("signinUrl", window.location.pathname + window.location.search);
                Setting.goToLinkSoft({props}, "/account");
                return;
              }
              if (res.data2.method === "POST") {
                setSamlResponse(res.data);
                setRedirectUrl(res.data2.redirectUrl);
                setRelayState(oAuthParams.relayState);
              } else {
                const SAMLResponse = res.data;
                const redirectUri = res.data2.redirectUrl;
                Setting.goToLink(`${redirectUri}${redirectUri.includes("?") ? "&" : "?"}SAMLResponse=${encodeURIComponent(SAMLResponse)}&RelayState=${encodeURIComponent(oAuthParams.relayState)}`);
              }
            }
          };

          if (res.status === "ok") {
            Setting.checkLoginMfa(res, vals, oAuthParams, loginHandler, getComponentThis());
          } else {
            Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
            if (shouldRefreshCaptcha) {
              refreshInlineCaptcha();
            }
          }
        }).finally(() => {
          localStorage.setItem("lastLoginOrg", vals?.organization || "");
          setLoginLoading(false);
        });
    }
  }, [userLang, captchaValues, isInlineCaptchaEnabled, loginMethod, type, getCurrentLoginMethod, populateOauthValues, applicationName, postCodeLoginAction, refreshInlineCaptcha, props, getComponentThis]);

  const checkCaptchaStatus = useCallback((vals) => {
    AuthBackend.getCaptchaStatus(vals)
      .then((res) => {
        if (res.status === "ok") {
          if (res.data) {
            setOpenCaptchaModal(true);
            setValues(vals);
            return null;
          }
        }
        login(vals);
      });
  }, [login]);

  const signInWithWebAuthn = useCallback((uname, vals) => {
    const oAuthParams = Util.getOAuthGetParameters();
    populateOauthValues(vals);
    const application = getApplicationObj();
    const usernameParam = `&name=${encodeURIComponent(uname)}`;
    return fetch(`${Setting.ServerUrl}/api/webauthn/signin/begin?owner=${application.organization}${uname ? usernameParam : ""}`, {
      method: "GET",
      credentials: "include",
    })
      .then(res => res.json())
      .then((credentialRequestOptions) => {
        if ("status" in credentialRequestOptions) {
          return Promise.reject(new Error(credentialRequestOptions.msg));
        }
        credentialRequestOptions.publicKey.challenge = UserWebauthnBackend.webAuthnBufferDecode(credentialRequestOptions.publicKey.challenge);

        if (uname) {
          credentialRequestOptions.publicKey.allowCredentials.forEach(function(listItem) {
            listItem.id = UserWebauthnBackend.webAuthnBufferDecode(listItem.id);
          });
        }

        return navigator.credentials.get({
          publicKey: credentialRequestOptions.publicKey,
        });
      })
      .then((assertion) => {
        const authData = assertion.response.authenticatorData;
        const clientDataJSON = assertion.response.clientDataJSON;
        const rawId = assertion.rawId;
        const sig = assertion.response.signature;
        const userHandle = assertion.response.userHandle;
        const resourceQuery = oAuthParams?.resource
          ? `&resource=${encodeURIComponent(oAuthParams.resource)}`
          : "";
        let finishUrl = `${Setting.ServerUrl}/api/webauthn/signin/finish?responseType=${vals["type"]}`;
        if (vals["type"] === "code") {
          finishUrl = `${Setting.ServerUrl}/api/webauthn/signin/finish?responseType=${vals["type"]}&clientId=${oAuthParams.clientId}&scope=${oAuthParams.scope}&redirectUri=${oAuthParams.redirectUri}&nonce=${oAuthParams.nonce}&state=${oAuthParams.state}&codeChallenge=${oAuthParams.codeChallenge}&challengeMethod=${oAuthParams.challengeMethod}${resourceQuery}`;
        }
        return fetch(finishUrl, {
          method: "POST",
          credentials: "include",
          body: JSON.stringify({
            id: assertion.id,
            rawId: UserWebauthnBackend.webAuthnBufferEncode(rawId),
            type: assertion.type,
            response: {
              authenticatorData: UserWebauthnBackend.webAuthnBufferEncode(authData),
              clientDataJSON: UserWebauthnBackend.webAuthnBufferEncode(clientDataJSON),
              signature: UserWebauthnBackend.webAuthnBufferEncode(sig),
              userHandle: UserWebauthnBackend.webAuthnBufferEncode(userHandle),
            },
          }),
        })
          .then(res => res.json()).then((res) => {
            if (res.status === "ok") {
              const responseType = vals["type"];
              if (responseType === "code") {
                postCodeLoginAction(res);
              } else if (responseType === "token" || responseType === "id_token") {
                const accessToken = res.data;
                Setting.goToLink(`${oAuthParams.redirectUri}#${responseType}=${accessToken}?state=${oAuthParams.state}&token_type=bearer`);
              } else {
                Setting.showMessage("success", i18next.t("login:Successfully logged in with WebAuthn credentials"));
                Setting.goToLink("/");
              }
            } else {
              Setting.showMessage("error", res.msg);
            }
          })
          .catch(error => {
            Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}${error}`);
          });
      }).catch(error => {
        Setting.showMessage("error", `${error.message}`);
      }).finally(() => {
        setLoginLoading(false);
      });
  }, [populateOauthValues, getApplicationObj, postCodeLoginAction]);

  const onFinish = useCallback((formValues) => {
    setLoginLoading(true);
    if (loginMethod === "webAuthn") {
      let uname = username;
      if (uname === null || uname === "") {
        uname = formValues["username"];
      }
      signInWithWebAuthn(uname, formValues);
      return;
    }
    if (loginMethod === "faceId") {
      let uname = username;
      if (uname === null || uname === "") {
        uname = formValues["username"];
      }
      const application = getApplicationObj();
      fetch(`${Setting.ServerUrl}/api/faceid-signin-begin?owner=${application.organization}&name=${uname}`, {
        method: "GET",
        credentials: "include",
        headers: {
          "Accept-Language": Setting.getAcceptLanguage(),
        },
      }).then(res => res.json())
        .then((res) => {
          if (res.status === "error") {
            setLoginLoading(false);
            Setting.showMessage("error", res.msg);
            return;
          }
          setOpenFaceRecognitionModal(true);
          setValues(formValues);
        });
      return;
    }
    if (loginMethod === "password" || loginMethod === "ldap") {
      const organization = getApplicationObj()?.organizationObj;
      const [passwordCipher, errorMessage] = Obfuscator.encryptByPasswordObfuscator(organization?.passwordObfuscatorType, organization?.passwordObfuscatorKey, formValues["password"]);
      if (errorMessage.length > 0) {
        Setting.showMessage("error", errorMessage);
        return;
      } else {
        formValues["password"] = passwordCipher;
      }
      const captchaRule = getCaptchaRule(getApplicationObj());
      const application = getApplicationObj();
      const inlineCaptchaEnabled = isInlineCaptchaEnabled(application);
      if (!inlineCaptchaEnabled) {
        if (captchaRule === CaptchaRule.Always) {
          setOpenCaptchaModal(true);
          setValues(formValues);
          return;
        } else if (captchaRule === CaptchaRule.Dynamic) {
          checkCaptchaStatus(formValues);
          return;
        } else if (captchaRule === CaptchaRule.InternetOnly) {
          checkCaptchaStatus(formValues);
          return;
        }
      } else {
        formValues["captchaType"] = captchaValues?.captchaType;
        formValues["captchaToken"] = captchaValues?.captchaToken;
        formValues["clientSecret"] = captchaValues?.clientSecret;
      }
    }
    login(formValues);
  }, [loginMethod, username, signInWithWebAuthn, getApplicationObj, getCaptchaRule, isInlineCaptchaEnabled, checkCaptchaStatus, captchaValues, login]);

  // --- Effects ---

  useEffect(() => {
    if (getApplicationObj() === undefined) {
      if (type === "login" || type === "saml") {
        if (applicationName === null) {
          return;
        }
        if (owner === null || type === "saml") {
          ApplicationBackend.getApplication("admin", applicationName)
            .then((res) => {
              if (res.status === "error") {
                onUpdateApplication(null);
                setMsg(res.msg);
                return;
              }
              onUpdateApplication(res.data);
            });
        } else {
          OrganizationBackend.getDefaultApplication("admin", owner)
            .then((res) => {
              if (res.status === "ok") {
                const application = res.data;
                onUpdateApplication(application);
                setApplicationName(res.data.name);
              } else {
                onUpdateApplication(null);
                Setting.showMessage("error", res.msg);
                props.history.push("/404");
              }
            });
        }
      } else if (type === "code" || type === "cas" || type === "device") {
        let loginParams;
        if (type === "cas") {
          loginParams = Util.getCasLoginParameters("admin", applicationName);
        } else if (type === "device") {
          loginParams = {userCode: userCode, type: type};
        } else {
          loginParams = Util.getOAuthGetParameters();
        }
        AuthBackend.getApplicationLogin(loginParams)
          .then((res) => {
            if (res.status === "ok") {
              const application = res.data;
              onUpdateApplication(application);
            } else {
              if (type === "device") {
                setUserCodeStatus("expired");
              }
              onUpdateApplication(null);
              setMsg(res.msg);
            }
          });
      } else {
        Setting.showMessage("error", `${i18next.t("general:Unknown authentication type")}: ${type}`);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (loginMethod === undefined) {
      const application = getApplicationObj();
      if (application) {
        setLoginMethod(getDefaultLoginMethod(application));
      }
    }
  }, [loginMethod, getApplicationObj, getDefaultLoginMethod]);

  useEffect(() => {
    if (props.application) {
      setLoginMethod(getDefaultLoginMethod(props.application));
    }
  }, [props.application, getDefaultLoginMethod]);

  useEffect(() => {
    if (props.account !== undefined && props.application) {
      if (props.account && props.account.owner === props.application?.organization) {
        const params = new URLSearchParams(props.location.search);
        const silentSignin = params.get("silentSignin");
        if (silentSignin !== null) {
          sendSilentSigninData("signing-in");
          const vals = {};
          vals["application"] = props.application.name;
          login(vals);
        }

        if (params.get("popup") === "1") {
          window.addEventListener("beforeunload", () => {
            sendPopupData({type: "windowClosed"}, params.get("redirect_uri"));
          });
        }

        if (props.application.enableAutoSignin && silentSignin === null) {
          const vals = {};
          vals["application"] = props.application.name;
          login(vals);
        }
      }
    }
  }, [props.account, props.application]); // eslint-disable-line react-hooks/exhaustive-deps

  // --- Helpers ---

  const isProviderVisible = (providerItem) => {
    if (mode === "signup") {
      return Setting.isProviderVisibleForSignUp(providerItem);
    } else {
      return Setting.isProviderVisibleForSignIn(providerItem);
    }
  };

  const renderOtherFormProvider = (application) => {
    if (Setting.inIframe()) {
      return null;
    }
    for (const providerConf of application.providers) {
      if (providerConf.provider?.type === "Google" && providerConf.rule === "OneTap" && props.preview !== "auto") {
        return (
          <GoogleOneTapLoginVirtualButton application={application} providerConf={providerConf} />
        );
      }
    }
    return null;
  };

  const switchLoginOrganization = (name) => {
    const searchParams = new URLSearchParams(window.location.search);
    const clientId = searchParams.get("client_id");
    if (clientId) {
      const clientIdSplited = clientId.split("-org-");
      searchParams.set("client_id", `${clientIdSplited[0]}-org-${name}`);
      Setting.goToLink(`/login/oauth/authorize?${searchParams.toString()}`);
      return;
    }
    const application = getApplicationObj();
    if (window.location.pathname.startsWith("/login/saml/authorize")) {
      Setting.goToLink(`/login/saml/authorize/${name}/${application.name}-org-${name}?${searchParams.toString()}`);
      return;
    }
    if (window.location.pathname.startsWith("/cas")) {
      Setting.goToLink(`/cas/${application.name}-org-${name}/${name}/login?${searchParams.toString()}`);
      return;
    }
    searchParams.set("orgChoiceMode", "None");
    Setting.goToLink(`/login/${name}?${searchParams.toString()}`);
  };

  const hasVerificationCodeSigninItem = (application) => {
    const targetApp = application || getApplicationObj();
    if (!targetApp || !targetApp.signinItems) {
      return false;
    }
    return targetApp.signinItems.some(item => item.name === "Verification code");
  };

  // --- Render helpers ---

  const renderCaptchaModal = (application, noModal) => {
    if (getCaptchaRule(getApplicationObj()) === CaptchaRule.Never) {
      return null;
    }
    const captchaProviderItems = getCaptchaProviderItems(application);
    const alwaysProviderItems = captchaProviderItems.filter(providerItem => providerItem.rule === "Always");
    const dynamicProviderItems = captchaProviderItems.filter(providerItem => providerItem.rule === "Dynamic");
    const internetOnlyProviderItems = captchaProviderItems.filter(providerItem => providerItem.rule === "Internet-Only");

    const captchaRule = getCaptchaRule(getApplicationObj());
    let provider = null;

    if (captchaRule === CaptchaRule.Always && alwaysProviderItems.length > 0) {
      provider = alwaysProviderItems[0].provider;
    } else if (captchaRule === CaptchaRule.Dynamic && dynamicProviderItems.length > 0) {
      provider = dynamicProviderItems[0].provider;
    } else if (captchaRule === CaptchaRule.InternetOnly && internetOnlyProviderItems.length > 0) {
      provider = internetOnlyProviderItems[0].provider;
    }

    if (!provider) {
      return null;
    }

    return <CaptchaModal
      owner={provider.owner}
      name={provider.name}
      visible={openCaptchaModal}
      noModal={noModal}
      onUpdateToken={(captchaType, captchaToken, clientSecret) => {
        setCaptchaValues({captchaType, captchaToken, clientSecret});
      }}
      onOk={(captchaType, captchaToken, clientSecret) => {
        const v = values;
        v["captchaType"] = captchaType;
        v["captchaToken"] = captchaToken;
        v["clientSecret"] = clientSecret;
        login(v);
        setOpenCaptchaModal(false);
      }}
      onCancel={() => { setOpenCaptchaModal(false); setLoginLoading(false); }}
      isCurrentProvider={true}
      innerRef={captchaRef}
    />;
  };

  const renderPasswordOrCodeInput = (signinItem) => {
    const application = getApplicationObj();
    if (loginMethod === "password" || loginMethod === "ldap") {
      return (
        <Col span={24}>
          <div>
            <Form.Item
              name="password"
              className="login-password"
              label={signinItem.label ? signinItem.label : null}
              rules={[{required: true, message: i18next.t("login:Please input your password!")}]}
            >
              <Input.Password
                className="login-password-input"
                prefix={<Lock className="w-4 h-4 text-neutral-500" />}
                type="password"
                placeholder={signinItem.placeholder ? signinItem.placeholder : i18next.t("general:Password")}
                disabled={loginMethod === "password" ? !Setting.isPasswordEnabled(application) : !Setting.isLdapEnabled(application)}
              />
            </Form.Item>
          </div>
        </Col>
      );
    } else if (loginMethod?.includes("verificationCode") && !hasVerificationCodeSigninItem(application)) {
      return (
        <Col span={24}>
          <div className="login-password">
            <Form.Item
              name="code"
              rules={[{required: true, message: i18next.t("login:Please input your code!")}]}
            >
              <SendCodeInput
                disabled={username?.length === 0 || !validEmailOrPhone}
                method={"login"}
                onButtonClickArgs={[username, validEmail ? "email" : "phone", Setting.getApplicationName(application)]}
                application={application}
                captchaValue={captchaValues}
                useInlineCaptcha={isInlineCaptchaEnabled(application)}
                refreshCaptcha={refreshInlineCaptcha}
              />
            </Form.Item>
          </div>
        </Col>
      );
    } else {
      return null;
    }
  };

  const renderCodeInput = (signinItem) => {
    const application = getApplicationObj();
    if (hasVerificationCodeSigninItem(application) && loginMethod?.includes("verificationCode")) {
      return (
        <Col span={24}>
          <Form.Item
            name="code"
            label={signinItem.label ? signinItem.label : null}
            rules={[{required: true, message: i18next.t("login:Please input your code!")}]}
            className="verification-code"
          >
            <SendCodeInput
              disabled={username?.length === 0 || !validEmailOrPhone}
              method={"login"}
              onButtonClickArgs={[username, validEmail ? "email" : "phone", Setting.getApplicationName(application)]}
              application={application}
              captchaValue={captchaValues}
              useInlineCaptcha={isInlineCaptchaEnabled(application)}
              refreshCaptcha={refreshInlineCaptcha}
            />
          </Form.Item>
        </Col>
      );
    } else {
      return null;
    }
  };

  const renderMethodChoiceBox = () => {
    const application = getApplicationObj();
    const items = [];

    const generateItemKey = (name, rule) => `${name}-${rule}`;

    const itemsMap = new Map([
      [generateItemKey("Password", "All"), {label: i18next.t("general:Password"), key: "password"}],
      [generateItemKey("Password", "Non-LDAP"), {label: i18next.t("general:Password"), key: "password"}],
      [generateItemKey("Verification code", "All"), {label: i18next.t("login:Verification code"), key: "verificationCode"}],
      [generateItemKey("Verification code", "Email only"), {label: i18next.t("login:Verification code"), key: "verificationCodeEmail"}],
      [generateItemKey("Verification code", "Phone only"), {label: i18next.t("login:Verification code"), key: "verificationCodePhone"}],
      [generateItemKey("WebAuthn", "None"), {label: i18next.t("login:WebAuthn"), key: "webAuthn"}],
      [generateItemKey("LDAP", "None"), {label: i18next.t("login:LDAP"), key: "ldap"}],
      [generateItemKey("Face ID", "None"), {label: i18next.t("login:Face ID"), key: "faceId"}],
      [generateItemKey("WeChat", "Tab"), {label: i18next.t("login:WeChat"), key: "wechat"}],
      [generateItemKey("WeChat", "None"), {label: i18next.t("login:WeChat"), key: "wechat"}],
    ]);

    application?.signinMethods?.forEach((signinMethod) => {
      if (signinMethod.rule === "Hide password") {
        return;
      }
      const item = itemsMap.get(generateItemKey(signinMethod.name, signinMethod.rule));
      if (item) {
        let label = signinMethod.name === signinMethod.displayName ? item.label : signinMethod.displayName;
        if (application?.signinMethods?.length >= 4 && label === "Verification code") {
          label = "Code";
        }
        items.push({label: label, key: item.key});
      }
    });

    if (items.length > 1) {
      return (
        <div>
          <Tabs className="signin-methods" items={items} size={"small"} activeKey={loginMethod} onChange={(key) => {
            setLoginMethod(key);
          }} centered>
          </Tabs>
        </div>
      );
    }
  };

  const renderFooter = (application, signinItem) => {
    return (
      <div className="text-center text-sm text-neutral-400">
        {
          !application.enableSignUp ? null : (
            signinItem.label ? Setting.renderSignupLink(application, signinItem.label) :
              (
                <React.Fragment>
                  {i18next.t("login:No account?")}&nbsp;
                  {
                    Setting.renderSignupLink(application, i18next.t("login:sign up now"))
                  }
                </React.Fragment>
              )
          )
        }
      </div>
    );
  };

  const renderBackButton = () => {
    if (orgChoiceMode === "None" || props.preview === "auto") {
      return (
        <button
          className="flex items-center justify-center w-10 h-10 rounded-lg border border-white/10 bg-transparent text-neutral-400 hover:text-white hover:border-white/20 transition-colors"
          onClick={() => history.back()}
          type="button"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
      );
    }
  };

  const renderFormItem = (application, signinItem) => {
    if (!signinItem.visible && signinItem.name !== "Forgot password?") {
      return null;
    }

    const resultItemKey = `${application.organization}_${application.name}_${signinItem.name}`;

    if (signinItem.name === "Logo") {
      return (
        <div key={resultItemKey} className="login-logo-box">
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          {Setting.renderHelmet(application)}
          {Setting.renderLogo(application)}
        </div>
      );
    } else if (signinItem.name === "Back button") {
      return (
        <div key={resultItemKey} className="back-button">
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          {renderBackButton()}
        </div>
      );
    } else if (signinItem.name === "Languages") {
      const languages = application.organizationObj.languages;
      if (languages.length <= 1) {
        const language = (languages.length === 1) ? languages[0] : "en";
        if (Setting.getLanguage() !== language) {
          Setting.setLanguage(language);
        }
        return null;
      }
      return (
        <div key={resultItemKey} className="login-languages">
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          <LanguageSelect languages={application.organizationObj.languages} onClick={key => { setUserLang(key); }} />
        </div>
      );
    } else if (signinItem.name === "Signin methods") {
      return (
        <div key={resultItemKey}>
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          {renderMethodChoiceBox()}
        </div>
      );
    } else if (signinItem.name === "Username") {
      if (loginMethod === "wechat") {
        return (<WeChatLoginPanel application={application} loginMethod={loginMethod} />);
      }

      if (loginMethod === "verificationCodePhone") {
        return <Form.Item className="signin-phone" required={true}>
          <Input.Group compact>
            <Form.Item
              name="countryCode"
              noStyle
              rules={[{required: true, message: i18next.t("signup:Please select your country code!")}]}
            >
              <CountryCodeSelect
                style={{width: "35%"}}
                countryCodes={getApplicationObj().organizationObj.countryCodes}
              />
            </Form.Item>
            <Form.Item
              name="username"
              dependencies={["countryCode"]}
              noStyle
              rules={[
                {required: true, message: i18next.t("signup:Please input your phone number!")},
                ({getFieldValue}) => ({
                  validator: (_, value) => {
                    if (!value) {
                      return Promise.resolve();
                    }
                    if (value && !Setting.isValidPhone(value, getFieldValue("countryCode"))) {
                      setValidEmailOrPhone(false);
                      return Promise.reject(i18next.t("signup:The input is not valid Phone!"));
                    }
                    setValidEmailOrPhone(true);
                    return Promise.resolve();
                  },
                }),
              ]}
            >
              <Input
                className="signup-phone-input"
                placeholder={signinItem.placeholder}
                style={{width: "65%", textAlign: "left"}}
                onChange={e => setUsername(e.target.value)}
              />
            </Form.Item>
          </Input.Group>
        </Form.Item>;
      }

      return (
        <div key={resultItemKey}>
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          <Form.Item
            name="username"
            className="login-username"
            label={signinItem.label ? signinItem.label : null}
            rules={[
              {
                required: loginMethod !== "webAuthn",
                message: () => {
                  switch (loginMethod) {
                  case "verificationCodeEmail":
                    return i18next.t("login:Please input your Email!");
                  case "verificationCodePhone":
                    return i18next.t("login:Please input your Phone!");
                  case "ldap":
                    return i18next.t("login:Please input your LDAP username!");
                  default:
                    return i18next.t("login:Please input your Email or Phone!");
                  }
                },
              },
              {
                validator: (_, value) => {
                  if (value === "") {
                    return Promise.resolve();
                  }
                  if (loginMethod === "verificationCode") {
                    if (!Setting.isValidEmail(value) && !Setting.isValidPhone(value)) {
                      setValidEmailOrPhone(false);
                      return Promise.reject(i18next.t("login:The input is not valid Email or phone number!"));
                    }
                    if (Setting.isValidEmail(value)) {
                      setValidEmail(true);
                    } else {
                      setValidEmail(false);
                    }
                  } else if (loginMethod === "verificationCodeEmail") {
                    if (!Setting.isValidEmail(value)) {
                      setValidEmail(false);
                      setValidEmailOrPhone(false);
                      return Promise.reject(i18next.t("login:The input is not valid Email!"));
                    } else {
                      setValidEmail(true);
                    }
                  } else if (loginMethod === "verificationCodePhone") {
                    if (!Setting.isValidPhone(value)) {
                      setValidEmailOrPhone(false);
                      return Promise.reject(i18next.t("login:The input is not valid phone number!"));
                    }
                  }
                  setValidEmailOrPhone(true);
                  return Promise.resolve();
                },
              },
            ]}
          >
            <Input
              id="input"
              className="login-username-input"
              prefix={loginMethod === "verificationCodePhone"
                ? <Phone className="w-4 h-4 text-neutral-500" />
                : loginMethod === "verificationCodeEmail"
                  ? <Mail className="w-4 h-4 text-neutral-500" />
                  : <User className="w-4 h-4 text-neutral-500" />}
              suffix={loginMethod?.includes("verificationCode") ? (
                <span
                  className="login-input-mode-toggle"
                  title={loginMethod === "verificationCodePhone" ? i18next.t("login:Switch to email") : i18next.t("login:Switch to phone")}
                  onClick={() => {
                    setLoginMethod(loginMethod === "verificationCodePhone" ? "verificationCodeEmail" : "verificationCodePhone");
                  }}
                >
                  {loginMethod === "verificationCodePhone"
                    ? <Mail className="w-4 h-4" />
                    : <Phone className="w-4 h-4" />}
                </span>
              ) : null}
              placeholder={getPlaceholder(signinItem.placeholder)}
              onChange={e => { setUsername(e.target.value); }}
            />
          </Form.Item>
        </div>
      );
    } else if (signinItem.name === "Password") {
      return (
        <div key={resultItemKey}>
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          {renderPasswordOrCodeInput(signinItem)}
        </div>
      );
    } else if (signinItem.name === "Verification code") {
      return (
        <div key={resultItemKey}>
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          {renderCodeInput(signinItem)}
        </div>
      );
    } else if (signinItem.name === "Forgot password?") {
      return (
        <div key={resultItemKey}>
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          <div className="login-forget-password">
            <Form.Item name="autoSignin" valuePropName="checked" noStyle>
              <Checkbox style={{float: "left"}}>
                {i18next.t("login:Auto sign in")}
              </Checkbox>
            </Form.Item>
            {
              signinItem.visible ? Setting.renderForgetLink(application, signinItem.label ? signinItem.label : i18next.t("login:Forgot password?")) : null
            }
          </div>
        </div>
      );
    } else if (signinItem.name === "Agreement") {
      return AgreementModal.isAgreementRequired(application) ? AgreementModal.renderAgreementFormItem(application, true, {}, {props, form: formRef, state: {}, setState: () => {}}) : null;
    } else if (signinItem.name === "Login button") {
      if (loginMethod === "wechat") {
        return null;
      }
      return (
        <Form.Item key={resultItemKey} className="login-button-box">
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          <button
            type="submit"
            disabled={loginLoading}
            className="login-button w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loginLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <LogIn className="w-4 h-4" />
            )}
            {
              loginMethod === "webAuthn" ? i18next.t("login:Sign in with WebAuthn") :
                loginMethod === "faceId" ? i18next.t("login:Sign in with Face ID") :
                  signinItem.label ? signinItem.label : i18next.t("login:Sign In")
            }
          </button>
          {
            loginMethod === "faceId" ?
              haveFaceIdProvider ? <Suspense fallback={null}><FaceRecognitionCommonModal visible={openFaceRecognitionModal} onOk={(FaceIdImage) => {
                const v = values;
                v["FaceIdImage"] = FaceIdImage;
                login(v);
                setOpenFaceRecognitionModal(false);
              }} onCancel={() => { setOpenFaceRecognitionModal(false); setLoginLoading(false); }} /></Suspense> :
                <Suspense fallback={null}>
                  <FaceRecognitionModal
                    visible={openFaceRecognitionModal}
                    onOk={(faceId) => {
                      const v = values;
                      v["faceId"] = faceId;
                      login(v);
                      setOpenFaceRecognitionModal(false);
                    }}
                    onCancel={() => { setOpenFaceRecognitionModal(false); setLoginLoading(false); }}
                  />
                </Suspense>
              :
              null
          }
          {
            application?.signinItems.map(si => si.name === "Captcha" && si.rule === "inline").includes(true) ? null : renderCaptchaModal(application, false)
          }
        </Form.Item>
      );
    } else if (signinItem.name === "Providers") {
      const showForm = Setting.isPasswordEnabled(application) || Setting.isCodeSigninEnabled(application) || Setting.isWebAuthnEnabled(application) || Setting.isLdapEnabled(application);
      if (signinItem.rule === "None" || signinItem.rule === "") {
        signinItem.rule = showForm ? "small" : "big";
      }
      const searchParams = new URLSearchParams(window.location.search);
      const providerHint = searchParams.get("provider_hint");

      return (
        <div key={resultItemKey}>
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          <Form.Item>
            {
              application.providers.filter(providerItem => isProviderVisible(providerItem)).sort((a, b) => {
                const order = (p) => {
                  if (p.provider.category === "Web3") {return 0;}
                  if (p.provider.type === "Google") {return 1;}
                  if (p.provider.type === "GitHub") {return 2;}
                  return 3;
                };
                return order(a) - order(b);
              }).map((providerItem, id) => {
                if (providerHint === providerItem.provider.name) {
                  goToLink(Provider.getAuthUrl(application, providerItem.provider, "signup"));
                  return;
                }
                return (
                  <span key={id} onClick={(e) => {
                    const agreementChecked = formRef.current?.getFieldValue("agreement");
                    if (agreementChecked !== undefined && typeof agreementChecked === "boolean" && !agreementChecked) {
                      e.preventDefault();
                      message.error(i18next.t("signup:Please accept the agreement!"));
                    }
                  }}>
                    {
                      ProviderButton.renderProviderLogo(providerItem.provider, application, null, null, signinItem.rule, props.location)
                    }
                  </span>
                );
              })
            }
            {renderOtherFormProvider(application)}
          </Form.Item>
        </div>
      );
    } else if (signinItem.name === "Captcha" && signinItem.rule === "inline") {
      return renderCaptchaModal(application, true);
    } else if (signinItem.name.startsWith("Text ") || signinItem?.isCustom) {
      return (
        <div key={resultItemKey} dangerouslySetInnerHTML={{__html: signinItem.customCss}} />
      );
    } else if (signinItem.name === "Signup link") {
      return (
        <div key={resultItemKey} style={{width: "100%"}} className="login-signup-link">
          <div dangerouslySetInnerHTML={{__html: ("<style>" + signinItem.customCss?.replaceAll("<style>", "").replaceAll("</style>", "") + "</style>")}} />
          {renderFooter(application, signinItem)}
        </div>
      );
    } else if (signinItem.name === "Select organization") {
      return (
        <Form.Item>
          <div key={resultItemKey} style={{width: "100%"}} className="login-organization-select">
            <OrganizationSelect style={{width: "100%"}} initValue={application.organization}
              onSelect={(value) => {
                switchLoginOrganization(value);
              }} />
          </div>
        </Form.Item>
      );
    }
  };

  const renderForm = (application) => {
    if (msg !== null) {
      return Util.renderMessage(msg);
    }

    if (mode === "signup" && !application.enableSignUp) {
      return (
        <div className="flex flex-col items-center gap-4 py-8">
          <div className="text-red-400 text-lg font-medium">{i18next.t("application:Sign Up Error")}</div>
          <div className="text-neutral-400 text-sm text-center">{i18next.t("application:The application does not allow to sign up new account")}</div>
          <button
            className="px-6 py-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors"
            onClick={() => Setting.redirectToLoginPage(application, props.history)}
          >
            {i18next.t("login:Sign In")}
          </button>
        </div>
      );
    }

    if (userCode && userCodeStatus === "success") {
      return (
        <div className="flex flex-col items-center gap-4 py-8">
          <div className="text-green-400 text-lg font-medium">{i18next.t("application:Logged in successfully")}</div>
        </div>
      );
    }

    const showForm = Setting.isPasswordEnabled(application) || Setting.isCodeSigninEnabled(application) || Setting.isWebAuthnEnabled(application) || Setting.isLdapEnabled(application) || Setting.isFaceIdEnabled(application);
    if (showForm) {
      let loginWidth = 320;
      if (Setting.getLanguage() === "fr") {
        loginWidth += 20;
      } else if (Setting.getLanguage() === "es") {
        loginWidth += 40;
      } else if (Setting.getLanguage() === "ru") {
        loginWidth += 10;
      }

      return (
        <Form
          name="normal_login"
          initialValues={{
            organization: application.organization,
            application: application.name,
            autoSignin: !application?.signinItems.map(signinItem => signinItem.name === "Forgot password?" && signinItem.rule === "Auto sign in - False")?.includes(true),
            username: prefilledUsername || (Conf.ShowGithubCorner ? "admin" : ""),
            password: Conf.ShowGithubCorner ? "123" : "",
          }}
          onFinish={(v) => {
            onFinish(v);
          }}
          style={{width: `${loginWidth}px`}}
          size="large"
          ref={formRef}
        >
          <Form.Item hidden={true} name="application" rules={[{required: true, message: i18next.t("application:Please input your application!")}]} />
          <Form.Item hidden={true} name="organization" rules={[{required: true, message: i18next.t("application:Please input your organization!")}]} />
          {
            application.signinItems?.map(signinItem => renderFormItem(application, signinItem))
          }
        </Form>
      );
    } else {
      return (
        <div style={{marginTop: "20px"}}>
          <div className="text-base text-left text-neutral-300">
            {i18next.t("login:To access")}&nbsp;
            <a target="_blank" rel="noreferrer" href={application.homepageUrl}>
              <span className="font-bold">{application.displayName}</span>
            </a>
            :
          </div>
          <br />
          {
            application?.signinItems.map(signinItem => signinItem.name === "Providers" || signinItem.name === "Signup link" ? renderFormItem(application, signinItem) : null)
          }
        </div>
      );
    }
  };

  const renderSignedInBox = () => {
    if (props.account === undefined || props.account === null) {
      sendSilentSigninData("user-not-logged-in");
      return null;
    }

    const application = getApplicationObj();
    if (props.account.owner !== application?.organization) {
      return null;
    }

    if (props.requiredEnableMfa) {
      return null;
    }

    if (userCode && userCodeStatus === "success") {
      return null;
    }

    return (
      <div>
        <div className="text-base text-left text-neutral-300">
          {i18next.t("login:Continue with")}&nbsp;:
        </div>
        <br />
        <div onClick={() => {
          const vals = {};
          vals["application"] = application.name;
          login(vals);
        }}>
          <SelfLoginButton account={props.account} />
        </div>
        <br />
        <br />
        <div className="text-base text-left text-neutral-300">
          {i18next.t("login:Or sign in with another account")}&nbsp;:
        </div>
      </div>
    );
  };

  const renderLoginPanel = (application) => {
    const orgMode = application.orgChoiceMode;

    if (isOrganizationChoiceBoxVisible(orgMode)) {
      return renderOrganizationChoiceBox(orgMode);
    }

    if (getVerifyTotp !== undefined) {
      return getVerifyTotp();
    } else {
      return (
        <React.Fragment>
          {renderSignedInBox()}
          {renderForm(application)}
        </React.Fragment>
      );
    }
  };

  const isOrganizationChoiceBoxVisible = (orgMode) => {
    if (orgChoiceMode === "None") {
      return false;
    }
    const path = props.match?.path;
    if (path === "/login" || path === "/login/:owner") {
      return orgMode === "Select" || orgMode === "Input";
    }
    return false;
  };

  const renderOrganizationChoiceBox = (orgMode) => {
    const renderChoiceBox = () => {
      switch (orgMode) {
      case "None":
        return null;
      case "Select":
        return (
          <div>
            <p className="text-lg text-neutral-300">
              {i18next.t("login:Please select an organization to sign in")}
            </p>
            <OrganizationSelect style={{width: "70%"}}
              onSelect={(value) => {
                Setting.goToLink(`/login/${value}?orgChoiceMode=None`);
              }} />
          </div>
        );
      case "Input":
        return (
          <div>
            <p className="text-lg text-neutral-300">
              {i18next.t("login:Please type an organization to sign in")}
            </p>
            <Form
              name="basic"
              onFinish={(v) => { Setting.goToLink(`/login/${v.organizationName}?orgChoiceMode=None`); }}
            >
              <Form.Item
                name="organizationName"
                rules={[{required: true, message: i18next.t("login:Please input your organization name!")}]}
              >
                <Input style={{width: "70%"}} onPressEnter={(e) => {
                  Setting.goToLink(`/login/${e.target.value}?orgChoiceMode=None`);
                }} />
              </Form.Item>
              <button type="submit" className="px-6 py-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors">
                {i18next.t("general:Confirm")}
              </button>
            </Form>
          </div>
        );
      default:
        return null;
      }
    };

    return (
      <div style={{height: 300, minWidth: 320}}>
        {renderChoiceBox()}
      </div>
    );
  };

  // --- Main render ---

  if (userCodeStatus === "expired") {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <div className="text-red-400 text-lg font-medium">{`Code ${i18next.t("subscription:Expired")}`}</div>
      </div>
    );
  }

  const application = getApplicationObj();
  if (application === undefined) {
    return null;
  }
  if (application === null) {
    return Util.renderMessageLarge({props}, msg);
  }

  if (samlResponse !== "") {
    return <RedirectForm samlResponse={samlResponse} redirectUrl={redirectUrl} relayState={relayState} />;
  }

  if (application.signinHtml !== "") {
    return (
      <div dangerouslySetInnerHTML={{__html: application.signinHtml}} />
    );
  }

  const visibleOAuthProviderItems = (application.providers === null) ? [] : application.providers.filter(providerItem => isProviderVisible(providerItem) && providerItem.provider?.category !== "SAML");
  if (props.preview !== "auto" && !Setting.isPasswordEnabled(application) && !Setting.isCodeSigninEnabled(application) && !Setting.isWebAuthnEnabled(application) && !Setting.isLdapEnabled(application) && visibleOAuthProviderItems.length === 1) {
    Setting.goToLink(Provider.getAuthUrl(application, visibleOAuthProviderItems[0].provider, "signup"));
    return (
      <div className="flex items-center justify-center w-full min-h-[60vh]">
        <Loader2 className="w-8 h-8 animate-spin text-white" />
      </div>
    );
  }

  const wechatSigninMethods = application.signinMethods?.filter(method => method.name === "WeChat" && method.rule === "Login page");

  return (
    <React.Fragment>
      <div className="login-content" style={{margin: props.preview ?? parseOffset(application.formOffset)}}>
        {Setting.inIframe() || Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCss}} />}
        {Setting.inIframe() || !Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCssMobile}} />}
        <div className={Setting.isDarkTheme(props.themeAlgorithm) ? "login-panel-dark" : "login-panel"}>
          <div className="side-image" style={{display: application.formOffset !== 4 ? "none" : null}}>
            <div dangerouslySetInnerHTML={{__html: application.formSideHtml}} />
          </div>
          <div className="login-form">
            <div>
              {renderLoginPanel(application)}
            </div>
          </div>
          {
            wechatSigninMethods?.length > 0 ? (<div className="flex justify-center items-center">
              <div>
                <h3 className="text-center" style={{width: 320}}>{i18next.t("provider:Please use WeChat to scan the QR code and follow the official account for sign in")}</h3>
                <WeChatLoginPanel application={application} loginMethod={loginMethod} />
              </div>
            </div>
            ) : null
          }
        </div>
      </div>
    </React.Fragment>
  );
}

export default withRouter(LoginPage);

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
import React, {useCallback, useEffect, useRef, useState} from "react";
import {ArrowLeft, User, Lock, CheckCircle, KeyRound} from "lucide-react";
import {Input} from "../components/ui/input";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from "../components/ui/select";
import * as AuthBackend from "./AuthBackend";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as Util from "./Util";
import * as Setting from "../Setting";
import i18next from "i18next";
import {SendCodeInput} from "../common/SendCodeInput";
import * as UserBackend from "../backend/UserBackend";
import {withRouter} from "react-router-dom";
import * as PasswordChecker from "../common/PasswordChecker";
import * as Obfuscator from "./Obfuscator";

function ForgetPage(props) {
  const queryParams = new URLSearchParams(location.search);

  const [applicationName] = useState(props.applicationName ?? props.match.params?.applicationName);
  const [msg, setMsg] = useState(null);
  const [name, setName] = useState(props.account ? props.account.name : queryParams.get("username"));
  const [phone, setPhone] = useState("");
  const [email, setEmail] = useState("");
  const [dest, setDest] = useState("");
  const [isVerifyTypeFixed, setIsVerifyTypeFixed] = useState(false);
  const [verifyType, setVerifyType] = useState("");
  const [current, setCurrent] = useState(queryParams.get("code") ? 2 : 0);
  const [code, setCode] = useState(queryParams.get("code"));
  // Step 1
  const [step1Username, setStep1Username] = useState(name ?? "");
  const [step1Error, setStep1Error] = useState("");
  // Step 2
  const [step2Code, setStep2Code] = useState("");
  const [step2Error, setStep2Error] = useState("");
  // Step 3
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [newPasswordError, setNewPasswordError] = useState("");
  const [confirmError, setConfirmError] = useState("");

  const getApplicationObj = useCallback(() => props.application, [props.application]);
  const onUpdateApplication = useCallback((application) => props.onUpdateApplication(application), [props.onUpdateApplication]);

  useEffect(() => {
    if (getApplicationObj() === undefined) {
      if (applicationName !== undefined) {
        ApplicationBackend.getApplication("admin", applicationName)
          .then((res) => {
            if (res.status === "error") {
              Setting.showMessage("error", res.msg);
              return;
            }
            onUpdateApplication(res.data);
          });
      } else {
        Setting.showMessage("error", i18next.t("forget:Unknown forget type") + ": " + applicationName);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const submitStep1 = (application) => (e) => {
    e.preventDefault();
    if (!step1Username?.trim()) {
      setStep1Error(i18next.t("forget:Please input your username!"));
      return;
    }
    setStep1Error("");
    AuthBackend.getEmailAndPhone(application.organization, step1Username)
      .then((res) => {
        if (res.status === "ok") {
          const p = res.data.phone;
          const e2 = res.data.email;
          if (!p && !e2) {
            Setting.showMessage("error", i18next.t("general:No verification method"));
          } else {
            setName(res.data.name);
            setPhone(p);
            setEmail(e2);
            const saveFields = (type, d, fixed) => {
              setVerifyType(type);
              setIsVerifyTypeFixed(fixed);
              setDest(d);
            };
            switch (res.data2) {
            case "email": saveFields("email", e2, true); break;
            case "phone": saveFields("phone", p, true); break;
            case "username":
              p !== "" ? saveFields("phone", p, false) : saveFields("email", e2, false);
            }
            setCurrent(1);
          }
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
  };

  const submitStep2 = (application) => (e) => {
    e.preventDefault();
    if (!step2Code) {
      setStep2Error(i18next.t("code:Please input your verification code!"));
      return;
    }
    setStep2Error("");
    UserBackend.verifyCode({
      application: application.name,
      organization: application.organization,
      username: dest,
      name: name,
      code: step2Code,
      type: "login",
    }).then(res => {
      if (res.status === "ok") {
        setCurrent(2);
        setCode(step2Code);
      } else {
        Setting.showMessage("error", res.msg);
      }
    });
  };

  const onFinish = async (application) => {
    const userOwner = application?.organizationObj?.name ?? "built-in";

    let pwError = "";
    const checkErr = PasswordChecker.checkPasswordComplexity(newPassword, application.organizationObj?.passwordOptions ?? []);
    if (checkErr !== "") {pwError = checkErr;}
    if (pwError) {
      setNewPasswordError(pwError);
      return;
    }
    setNewPasswordError("");

    if (!confirmPassword) {
      setConfirmError(i18next.t("signup:Please confirm your password!"));
      return;
    }
    if (newPassword !== confirmPassword) {
      setConfirmError(i18next.t("signup:Your confirmed password is inconsistent with the password!"));
      return;
    }
    setConfirmError("");

    if (queryParams.get("code")) {
      const res = await UserBackend.verifyCode({
        application: application.name,
        organization: userOwner,
        username: queryParams.get("dest"),
        name: name,
        code: code,
        type: "login",
      });
      if (res.status !== "ok") {
        Setting.showMessage("error", res.msg);
        return;
      }
    }

    let encryptedNewPassword = newPassword;
    const organization = application.organizationObj;
    if (organization?.passwordObfuscatorType && organization.passwordObfuscatorType !== "Plain") {
      const [passwordCipher, errorMessage] = Obfuscator.encryptByPasswordObfuscator(
        organization.passwordObfuscatorType,
        organization.passwordObfuscatorKey,
        newPassword
      );
      if (errorMessage.length > 0) {
        Setting.showMessage("error", errorMessage);
        return;
      }
      encryptedNewPassword = passwordCipher;
    }

    UserBackend.setPassword(userOwner, name, "", encryptedNewPassword, code).then(res => {
      if (res.status === "ok") {
        const linkInStorage = sessionStorage.getItem("signinUrl");
        if (linkInStorage !== null && linkInStorage !== "") {
          Setting.goToLinkSoft({props}, linkInStorage);
        } else {
          Setting.redirectToLoginPage(application, props.history);
        }
      } else {
        Setting.showMessage("error", res.msg);
      }
    });
  };

  const stepBack = () => {
    if (current > 0) {
      setCurrent(current - 1);
    } else if (props.history.length > 1) {
      props.history.goBack();
    } else {
      Setting.redirectToLoginPage(getApplicationObj(), props.history);
    }
  };

  const renderStepIndicator = () => {
    const steps = [
      {label: i18next.t("forget:Account"), icon: <User className="w-4 h-4" />},
      {label: i18next.t("forget:Verify"), icon: <KeyRound className="w-4 h-4" />},
      {label: i18next.t("forget:Reset"), icon: <Lock className="w-4 h-4" />},
    ];
    return (
      <div className="flex items-center justify-center gap-2 my-8">
        {steps.map((step, idx) => (
          <React.Fragment key={idx}>
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              idx === current
                ? "bg-white/10 text-white"
                : idx < current
                  ? "text-white/60"
                  : "text-white/30"
            }`}>
              <div className={`flex items-center justify-center w-6 h-6 rounded-full text-xs ${
                idx === current
                  ? "bg-white text-black"
                  : idx < current
                    ? "bg-white/30 text-white"
                    : "bg-white/10 text-white/30"
              }`}>
                {idx < current ? <CheckCircle className="w-3.5 h-3.5" /> : idx + 1}
              </div>
              <span className="hidden sm:inline">{step.label}</span>
            </div>
            {idx < steps.length - 1 && (
              <div className={`w-8 h-px ${idx < current ? "bg-white/30" : "bg-white/10"}`} />
            )}
          </React.Fragment>
        ))}
      </div>
    );
  };

  const renderForm = (application) => {
    return (
      <React.Fragment>
        {current === 0 && (
          <form onSubmit={submitStep1(application)} style={{width: "300px"}}>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500" />
              <Input
                className="pl-9"
                value={step1Username}
                onChange={(e) => { setStep1Username(e.target.value); setStep1Error(""); }}
                placeholder={i18next.t("login:Username, email, or phone")}
              />
            </div>
            {step1Error && <p className="text-sm text-red-500 mt-1">{step1Error}</p>}
            <br />
            <button type="submit" className="w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors">
              {i18next.t("forget:Next Step")}
            </button>
          </form>
        )}

        {current === 1 && (
          <form onSubmit={submitStep2(application)} style={{width: "300px"}}>
            <Select
              value={dest}
              disabled={isVerifyTypeFixed}
              onValueChange={(v) => {
                setDest(v);
                setVerifyType(v?.indexOf("@") === -1 ? "phone" : "email");
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder={i18next.t("forget:Choose email or phone")} />
              </SelectTrigger>
              <SelectContent>
                {phone !== "" && <SelectItem value={phone}>{phone}</SelectItem>}
                {email !== "" && <SelectItem value={email}>{email}</SelectItem>}
              </SelectContent>
            </Select>
            <div className="mt-3">
              <SendCodeInput
                value={step2Code}
                onChange={(v) => { setStep2Code(v); setStep2Error(""); }}
                disabled={dest === ""}
                method={"forget"}
                onButtonClickArgs={[dest, verifyType, Setting.getApplicationName(application), name]}
                application={application}
              />
            </div>
            {step2Error && <p className="text-sm text-red-500 mt-1">{step2Error}</p>}
            <br />
            <button type="submit" className="w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors">
              {i18next.t("forget:Next Step")}
            </button>
          </form>
        )}

        {current === 2 && (
          <form onSubmit={(e) => { e.preventDefault(); onFinish(application); }} style={{width: "300px"}}>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500" />
              <Input
                type="password"
                className="pl-9"
                value={newPassword}
                onChange={(e) => { setNewPassword(e.target.value); setNewPasswordError(""); }}
                placeholder={i18next.t("general:Password")}
              />
            </div>
            {newPasswordError && <p className="text-sm text-red-500 mt-1">{newPasswordError}</p>}
            <div className="relative mt-3">
              <CheckCircle className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500" />
              <Input
                type="password"
                className="pl-9"
                value={confirmPassword}
                onChange={(e) => { setConfirmPassword(e.target.value); setConfirmError(""); }}
                placeholder={i18next.t("general:Confirm")}
              />
            </div>
            {confirmError && <p className="text-sm text-red-500 mt-1">{confirmError}</p>}
            <br />
            <button type="submit" className="w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors">
              {i18next.t("forget:Change Password")}
            </button>
          </form>
        )}
      </React.Fragment>
    );
  };

  const application = getApplicationObj();
  if (application === undefined) {
    return null;
  }
  if (application === null) {
    return Util.renderMessageLarge({props}, msg);
  }

  return (
    <React.Fragment>
      <div className="forget-content" style={{padding: Setting.isMobile() ? "0" : null, boxShadow: Setting.isMobile() ? "none" : null}}>
        {Setting.inIframe() || Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCss}} />}
        {Setting.inIframe() || !Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCssMobile}} />}
        <button
          type="button"
          className="flex items-center justify-center w-10 h-10 rounded-lg border border-white/10 bg-transparent text-neutral-400 hover:text-white hover:border-white/20 transition-colors"
          style={{position: "relative", left: Setting.isMobile() ? "10px" : "-90px", top: 0}}
          onClick={() => stepBack()}
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div className="flex flex-col items-center justify-center">
          <div className="mt-20 mb-3 text-center">
            {Setting.renderHelmet(application)}
            {Setting.renderLogo(application)}
          </div>
          <div className="text-center text-2xl font-semibold text-white mb-2">
            {i18next.t("forget:Reset password")}
          </div>
          {renderStepIndicator()}
          <div className="mt-4 text-center">
            {renderForm(application)}
          </div>
        </div>
      </div>
    </React.Fragment>
  );
}

export default withRouter(ForgetPage);

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
import React, {useCallback, useEffect, useState} from "react";
import {CheckCircle, LogIn, Loader2} from "lucide-react";
import i18next from "i18next";
import {authConfig} from "./Auth";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as Setting from "../Setting";
import * as AuthBackend from "./AuthBackend";

function ResultPage(props) {
  const [applicationName] = useState(
    props.match.params.applicationName !== undefined ? props.match.params.applicationName : authConfig.appName
  );
  const [application, setApplication] = useState(null);

  const onUpdateApplication = useCallback((app) => {
    props.onUpdateApplication(app);
  }, [props.onUpdateApplication]);

  useEffect(() => {
    if (applicationName !== undefined) {
      ApplicationBackend.getApplication("admin", applicationName)
        .then((res) => {
          if (res.status === "error") {
            Setting.showMessage("error", res.msg);
            return;
          }
          onUpdateApplication(res.data);
          setApplication(res.data);
        });
    } else {
      Setting.showMessage("error", `${i18next.t("general:Unknown application name")}: ${applicationName}`);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSignIn = () => {
    AuthBackend.getAccount()
      .then((res) => {
        if (res.status === "ok" && res.data) {
          const linkInStorage = sessionStorage.getItem("signinUrl");
          if (linkInStorage !== null && linkInStorage !== "") {
            window.location.href = linkInStorage;
          } else {
            Setting.goToLink("/");
          }
        } else {
          Setting.redirectToLoginPage(application, props.history);
        }
      });
  };

  if (application === null) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="w-8 h-8 animate-spin text-white" />
      </div>
    );
  }

  return (
    <div className="flex flex-1 items-center justify-center min-h-[60vh]">
      <div className="w-full max-w-md mx-auto p-8 rounded-xl border border-white/10 bg-white/[0.03]">
        <div className="text-center">
          {Setting.renderHelmet(application)}
          {Setting.renderLogo(application)}
          <div className="mt-8 mb-4 flex justify-center">
            <CheckCircle className="w-16 h-16 text-green-400" />
          </div>
          <h2 className="text-xl font-semibold text-white mb-2">
            {i18next.t("signup:Your account has been created!")}
          </h2>
          <p className="text-neutral-400 text-sm mb-8">
            {i18next.t("signup:Please click the below button to sign in")}
          </p>
          <button
            onClick={handleSignIn}
            className="w-full h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors"
          >
            <LogIn className="w-4 h-4" />
            {i18next.t("login:Sign In")}
          </button>
        </div>
      </div>
    </div>
  );
}

export default ResultPage;

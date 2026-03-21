// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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
import {Shield, Check, Loader2} from "lucide-react";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as ConsentBackend from "../backend/ConsentBackend";
import * as Setting from "../Setting";
import i18next from "i18next";
import {withRouter} from "react-router-dom";
import * as Util from "./Util";

function ConsentPage(props) {
  const params = new URLSearchParams(window.location.search);
  const [applicationName] = useState(props.match?.params?.applicationName || params.get("application"));
  const [scopeDescriptions, setScopeDescriptions] = useState([]);
  const [granting, setGranting] = useState(false);
  const [oAuthParams] = useState(Util.getOAuthGetParameters());

  const getApplicationObj = useCallback(() => props.application, [props.application]);

  useEffect(() => {
    if (!applicationName) {return;}
    ApplicationBackend.getApplication("admin", applicationName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }
        props.onUpdateApplication(res.data);
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const application = getApplicationObj();
    if (!oAuthParams?.scope || !application) {return;}

    const scopes = oAuthParams.scope.split(" ").map(s => s.trim()).filter(Boolean);
    const customScopes = application.customScopes || [];
    const customScopesMap = {};
    customScopes.forEach(s => {
      if (s?.scope) {customScopesMap[s.scope] = s;}
    });

    const descriptions = scopes
      .map(scope => {
        const item = customScopesMap[scope];
        if (item) {
          return {...item, displayName: item.displayName || item.scope};
        }
        return {
          scope: scope,
          displayName: scope,
          description: i18next.t("consent:This scope is not defined in the application"),
        };
      })
      .filter(Boolean);

    setScopeDescriptions(descriptions);
  }, [getApplicationObj, oAuthParams]);

  const handleGrant = () => {
    const application = getApplicationObj();
    setGranting(true);

    const consent = {
      owner: application.owner,
      application: application.owner + "/" + application.name,
      grantedScopes: scopeDescriptions.map(s => s.scope),
    };

    ConsentBackend.grantConsent(consent, oAuthParams)
      .then((res) => {
        if (res.status === "ok") {
          const code = res.data;
          const concatChar = oAuthParams?.redirectUri?.includes("?") ? "&" : "?";
          const redirectUrl = `${oAuthParams.redirectUri}${concatChar}code=${code}&state=${oAuthParams.state}`;
          Setting.goToLink(redirectUrl);
        } else {
          Setting.showMessage("error", res.msg);
          setGranting(false);
        }
      });
  };

  const handleDeny = () => {
    const concatChar = oAuthParams?.redirectUri?.includes("?") ? "&" : "?";
    Setting.goToLink(`${oAuthParams.redirectUri}${concatChar}error=access_denied&error_description=User denied consent&state=${oAuthParams.state}`);
  };

  const application = getApplicationObj();

  if (application === undefined) {
    return null;
  }

  if (!application) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-red-400 text-lg font-medium">{i18next.t("general:Invalid application")}</div>
      </div>
    );
  }

  const isScopeEmpty = scopeDescriptions.length === 0;

  return (
    <div className="flex items-center justify-center min-h-[60vh] px-4">
      <div className="w-full max-w-md p-8 rounded-xl border border-white/10 bg-white/[0.03]">
        {/* Header */}
        <div className="text-center mb-6">
          {application.logo && (
            <div className="mb-4 flex justify-center">
              <img
                src={application.logo}
                alt={application.displayName || application.name}
                className="h-14 object-contain"
              />
            </div>
          )}
          <h2 className="text-xl font-semibold text-white">
            {i18next.t("consent:Authorization Request")}
          </h2>
        </div>

        {/* App info */}
        <div className="mb-8 text-center">
          <p className="text-sm text-neutral-400 leading-relaxed">
            <span className="font-semibold text-white">{application.displayName || application.name}</span>
            {" "}{i18next.t("consent:wants to access your account")}
          </p>
          {application.homepageUrl && (
            <a href={application.homepageUrl} target="_blank" rel="noopener noreferrer"
              className="text-xs text-neutral-500 hover:text-neutral-300 transition-colors">
              {application.homepageUrl}
            </a>
          )}
        </div>

        {/* Scopes */}
        <div className="mb-8">
          <div className="flex items-center gap-2 text-sm text-neutral-400 mb-4">
            <Shield className="w-4 h-4" />
            {i18next.t("consent:This application is requesting")}
          </div>
          <div className="space-y-3">
            {scopeDescriptions.map((item, idx) => (
              <div key={idx} className="flex items-start gap-3 px-3 py-2 rounded-lg bg-white/[0.03] border border-white/5">
                <Check className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <div>
                  <div className="text-sm font-medium text-white">{item.displayName || item.scope}</div>
                  {item.description && (
                    <div className="text-xs text-neutral-500 mt-0.5">{item.description}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Buttons */}
        <div className="flex gap-3 mb-6">
          <button
            onClick={handleGrant}
            disabled={granting || isScopeEmpty}
            className="flex-1 h-11 flex items-center justify-center gap-2 rounded-lg bg-white text-black font-medium text-sm hover:bg-neutral-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {granting && <Loader2 className="w-4 h-4 animate-spin" />}
            {i18next.t("consent:Allow")}
          </button>
          <button
            onClick={handleDeny}
            disabled={granting || isScopeEmpty}
            className="flex-1 h-11 flex items-center justify-center rounded-lg border border-white/10 bg-transparent text-neutral-300 font-medium text-sm hover:border-white/20 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {i18next.t("consent:Deny")}
          </button>
        </div>

        {/* Disclaimer */}
        <div className="px-4 py-3 rounded-lg bg-white/[0.02] border border-white/5">
          <p className="text-xs text-neutral-500 text-center leading-relaxed">
            {i18next.t("consent:By clicking Allow, you allow this app to use your information")}
          </p>
        </div>
      </div>
    </div>
  );
}

export default withRouter(ConsentPage);

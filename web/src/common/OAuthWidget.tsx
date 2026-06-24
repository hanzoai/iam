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

import React, {useEffect, useState} from "react";
import i18next from "i18next";
import * as UserBackend from "../backend/UserBackend";
import * as Setting from "../Setting";
import * as Provider from "../auth/Provider";
import * as AuthBackend from "../auth/AuthBackend";
import {goToWeb3Url} from "../auth/ProviderButton";
import AccountAvatar from "../account/AccountAvatar";
import {WechatOfficialAccountModal} from "../auth/Util";

interface OAuthWidgetProps {
  application: any;
  user: any;
  account: any;
  providerItem: any;
  labelSpan: number;
  onUpdateUserField: (key: string, value: any) => void;
  onUnlinked: () => void;
}

const OAuthWidget = (props: OAuthWidgetProps) => {
  const {application, user, account, providerItem, labelSpan, onUnlinked} = props;
  const [addressOptions, setAddressOptions] = useState<any[]>([]);
  const [affiliationOptions, setAffiliationOptions] = useState<any[]>([]);

  useEffect(() => {
    getAddressOptions(application);
    getAffiliationOptions(application, user);
  }, []);

  const getAddressOptions = (app: any) => {
    if (app.affiliationUrl === "") {
      return;
    }
    const addressUrl = app.affiliationUrl.split("|")[0];
    UserBackend.getAddressOptions(addressUrl)
      .then((opts: any) => {
        setAddressOptions(opts);
      });
  };

  const getAffiliationOptions = (app: any, u: any) => {
    if (app.affiliationUrl === "") {
      return;
    }
    if (!u.address || u.address.length === 0) {
      return;
    }
    const affiliationUrl = app.affiliationUrl.split("|")[1];
    const code = u.address[u.address.length - 1];
    UserBackend.getAffiliationOptions(affiliationUrl, code)
      .then((opts: any) => {
        setAffiliationOptions(opts);
      });
  };

  const getProviderLink = (u: any, provider: any) => {
    if (provider.type === "GitHub") {
      return `https://github.com/${getUserProperty(u, provider.type, "username")}`;
    } else if (provider.type === "Google") {
      return "https://mail.google.com";
    } else {
      return "";
    }
  };

  const getUserProperty = (u: any, providerType: string, propertyName: string) => {
    const key = `oauth_${providerType}_${propertyName}`;
    if (u.properties === null) {return "";}
    return u.properties[key];
  };

  const unlinkUser = (providerType: string, linkedValue: string) => {
    // Native wallet login keeps no client-side token (cookie session only),
    // so unlinking is purely a server call for every provider type.
    const body = {
      providerType: providerType,
      user: user,
    };
    AuthBackend.unlink(body)
      .then((res: any) => {
        if (res.status === "ok") {
          Setting.showMessage("success", "Unlinked successfully");
          onUnlinked();
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to unlink")}: ${res.msg}`);
        }
      });
  };

  const provider = providerItem.provider;
  const linkedValue = user[provider.type.toLowerCase()];
  const profileUrl = getProviderLink(user, provider);
  const id = getUserProperty(user, provider.type, "id");
  const username = getUserProperty(user, provider.type, "username");
  const displayName = getUserProperty(user, provider.type, "displayName");
  const email = getUserProperty(user, provider.type, "email");
  let avatarUrl = getUserProperty(user, provider.type, "avatarUrl");

  if (avatarUrl === "" || avatarUrl === undefined) {
    avatarUrl = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAQAAACROWYpAAAAHElEQVR42mNkoAAwjmoe1TyqeVTzqOZRzcNZMwB18wAfEFQkPQAAAABJRU5ErkJggg==";
  }

  let name = (username === undefined) ? displayName : `${displayName} (${username})`;
  if (name === undefined) {
    if (id !== undefined) {
      name = id;
    } else if (email !== undefined) {
      name = email;
    } else {
      name = linkedValue;
    }
  }

  let linkButtonWidth = "110px";
  if (Setting.getLanguage() === "id") {
    linkButtonWidth = "160px";
  }

  return (
    <div className="flex items-start mt-5 gap-4">
      <div className="mt-1 min-w-0" style={{flex: `0 0 ${(labelSpan / 24) * 100}%`}}>
        <span className="flex items-center gap-1">
          {Setting.getProviderLogo(provider)}
          <span className="text-sm text-gray-400 ml-1">{`${provider.type}:`}</span>
        </span>
      </div>
      <div className="flex-1 flex items-center gap-2">
        <AccountAvatar style={{marginRight: "10px"}} size={30} src={avatarUrl} alt={name} referrerPolicy="no-referrer" />
        <span
          className="text-sm text-white truncate inline-block"
          style={{
            width: labelSpan === 3 ? "300px" : "200px",
            display: Setting.isMobile() ? "inline" : "inline-block",
          }}
          title={name}
        >
          {linkedValue === "" ? (
            `(${i18next.t("general:empty")})`
          ) : (
            profileUrl === "" ? name : (
              <a target="_blank" rel="noreferrer" href={profileUrl} className="text-white hover:underline">
                {name}
              </a>
            )
          )}
        </span>
        {linkedValue === "" ? (
          provider.category === "Web3" ? (
            <button
              style={{marginLeft: "20px", width: linkButtonWidth}}
              className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50"
              disabled={user.id !== account.id}
              onClick={() => goToWeb3Url(application, provider, "link")}
            >
              {i18next.t("user:Link")}
            </button>
          ) : (
            provider.type === "WeChat" && provider.clientId2 !== "" && provider.clientSecret2 !== "" && provider.disableSsl === true && !navigator.userAgent.includes("MicroMessenger") ? (
              <button
                style={{marginLeft: "20px", width: linkButtonWidth}}
                className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50"
                disabled={user.id !== account.id}
                onClick={() => {
                  WechatOfficialAccountModal(application, provider, "link");
                }}
              >
                {i18next.t("user:Link")}
              </button>
            ) : (
              <a href={user.id !== account.id ? undefined : Provider.getAuthUrl(application, provider, "link")}>
                <button
                  style={{marginLeft: "20px", width: linkButtonWidth}}
                  className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50"
                  disabled={user.id !== account.id}
                >
                  {i18next.t("user:Link")}
                </button>
              </a>
            )
          )
        ) : (
          <button
            disabled={!providerItem.canUnlink && !Setting.isAdminUser(account)}
            style={{marginLeft: "20px", width: linkButtonWidth}}
            className="px-4 py-2 text-sm border border-white/20 text-white rounded-lg hover:bg-white/10 transition-colors disabled:opacity-50"
            onClick={() => unlinkUser(provider.type, linkedValue)}
          >
            {i18next.t("user:Unlink")}
          </button>
        )}
      </div>
    </div>
  );
};

export default OAuthWidget;

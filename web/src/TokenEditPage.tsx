// @ts-nocheck
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
import * as TokenBackend from "./backend/TokenBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import copy from "copy-to-clipboard";
import {jwtDecode} from "jwt-decode";
import {Button} from "./components/ui/button";
import {Copy} from "lucide-react";

interface TokenEditPageProps {
  account: any;
  history: any;
  match: any;
  location: any;
}

function TokenEditPage(props: TokenEditPageProps) {
  const {account, history, match, location} = props;
  const tokenNameFromUrl = match.params.tokenName;

  const [tokenName, setTokenName] = useState(tokenNameFromUrl);
  const [token, setToken] = useState<any>(null);
  const [mode] = useState(location.mode ?? "edit");

  useEffect(() => { getToken(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function getToken() {
    TokenBackend.getToken("admin", tokenNameFromUrl).then((res: any) => {
      if (res.data === null) { history.push("/404"); return; }
      if (res.status === "error") { Setting.showMessage("error", res.msg); return; }
      setToken(res.data);
    });
  }

  function updateField(key: string, value: any) {
    setToken({...token, [key]: value});
  }

  function parseAccessToken(accessToken: string): string {
    try {
      const parsedHeader = JSON.stringify(jwtDecode(accessToken, {header: true} as any), null, 2);
      const parsedPayload = JSON.stringify(jwtDecode(accessToken), null, 2);
      return parsedHeader + "." + parsedPayload;
    } catch (error: any) {
      return error.message;
    }
  }

  function submitEdit(exitAfterSave: boolean) {
    const tokenCopy = Setting.deepCopy(token);
    TokenBackend.updateToken(token.owner, tokenName, tokenCopy).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully saved"));
        setTokenName(token.name);
        if (exitAfterSave) history.push("/tokens");
        else history.push(`/tokens/${token.name}`);
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
        updateField("name", tokenName);
      }
    }).catch((error: any) => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
  }

  function handleDelete() {
    TokenBackend.deleteToken(token).then((res: any) => {
      if (res.status === "ok") history.push("/tokens");
      else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    }).catch((error: any) => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
  }

  if (!token) return null;

  const parsedResult = parseAccessToken(token.accessToken);

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("token:New Token") : i18next.t("token:Edit Token")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>

        <div className="p-6 space-y-5">
          {[
            {label: i18next.t("general:Name"), key: "name"},
            {label: i18next.t("general:Application"), key: "application"},
            {label: i18next.t("general:Organization"), key: "organization", disabled: !Setting.isAdminUser(account)},
            {label: i18next.t("general:User"), key: "user"},
            {label: i18next.t("token:Authorization code"), key: "code"},
            {label: i18next.t("token:Expires in"), key: "expiresIn", type: "number"},
            {label: i18next.t("provider:Scope"), key: "scope"},
            {label: i18next.t("token:Token type"), key: "tokenType"},
          ].map(({label, key, disabled, type}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <input type={type || "text"} className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={disabled} value={token[key] ?? ""} onChange={e => updateField(key, type === "number" ? parseInt(e.target.value) || 0 : e.target.value)} />
            </div>
          ))}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-zinc-400">{i18next.t("token:Access token")}</label>
                <Button variant="outline" size="sm" disabled={!token.accessToken} onClick={() => { copy(token.accessToken); Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully")); }}>
                  <Copy className="w-3 h-3 mr-1" />{i18next.t("token:Copy access token")}
                </Button>
              </div>
              <textarea className="w-full h-[300px] bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-xs font-mono resize-none" value={token.accessToken} onChange={e => updateField("accessToken", e.target.value)} />
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-zinc-400">{i18next.t("token:Parsed result")}</label>
                <Button variant="outline" size="sm" disabled={!parsedResult.includes("\"alg\":")} onClick={() => { copy(parsedResult); Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully")); }}>
                  <Copy className="w-3 h-3 mr-1" />{i18next.t("token:Copy parsed result")}
                </Button>
              </div>
              <textarea className="w-full h-[300px] bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-xs font-mono resize-none" value={parsedResult} readOnly />
            </div>
          </div>
        </div>
      </div>

      <div className="flex gap-3 px-6">
        <Button variant="outline" size="lg" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
        <Button size="lg" onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
        {mode === "add" && <Button variant="outline" size="lg" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
      </div>
    </div>
  );
}

export default TokenEditPage;

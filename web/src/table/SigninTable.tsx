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

// @ts-nocheck
import React, {useCallback} from "react";
import {ArrowDown, ArrowUp, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import i18next from "i18next";
import Editor from "../common/Editor";

export const SigninTableDefaultCssMap = {
  "Back button": ".back-button {\n      top: 65px;\n      left: 15px;\n      position: absolute;\n}\n.back-inner-button{}",
  "Languages": ".login-languages {\n    top: 55px;\n    right: 5px;\n    position: absolute;\n}",
  "Logo": ".login-logo-box {}",
  "Signin methods": ".signin-methods {}",
  "Username": ".login-username {}\n.login-username-input{}",
  "Password": ".login-password {}\n.login-password-input{}",
  "Verification code": ".verification-code {}\n.verification-code-input{}",
  "Agreement": ".login-agreement {}",
  "Forgot password?": ".login-forget-password {\n    display: inline-flex;\n    justify-content: space-between;\n    width: 320px;\n    margin-bottom: 25px;\n}",
  "Login button": ".login-button-box {\n    margin-bottom: 5px;\n}\n.login-button {\n    width: 100%;\n}",
  "Signup link": ".login-signup-link {\n    margin-bottom: 24px;\n    display: flex;\n    justify-content: end;\n}",
  "Providers": ".provider-img {\n      width: 30px;\n      margin: 5px;\n}\n.provider-big-img {\n      margin-bottom: 10px;\n}",
};

function SigninTable({title, table: rawTable, onUpdateTable}) {
  const table = rawTable ?? [];

  const updateTable = useCallback((tbl) => {
    onUpdateTable(tbl);
  }, [onUpdateTable]);

  const updateField = useCallback((tbl, index, key, value) => {
    tbl[index][key] = value;
    if (key === "name" && value === "Captcha") {
      tbl[index]["rule"] = "pop up";
    }
    updateTable([...tbl]);
  }, [updateTable]);

  const addRow = useCallback((tbl) => {
    const row = {name: Setting.getNewRowNameForTable(tbl, "Please select a signin item"), visible: true, required: true, rule: "None"};
    let newTable = tbl ?? [];
    newTable = Setting.addRow(newTable, row);
    updateTable(newTable);
  }, [updateTable]);

  const addCustomRow = useCallback((tbl) => {
    const randomName = "Text " + Date.now().toString();
    const row = {name: Setting.getNewRowNameForTable(tbl, randomName), visible: true, isCustom: true};
    let newTable = tbl ?? [];
    newTable = Setting.addRow(newTable, row);
    updateTable(newTable);
  }, [updateTable]);

  const deleteRow = useCallback((tbl, i) => {
    updateTable(Setting.deleteRow(tbl, i));
  }, [updateTable]);

  const upRow = useCallback((tbl, i) => {
    updateTable(Setting.swapRow(tbl, i - 1, i));
  }, [updateTable]);

  const downRow = useCallback((tbl, i) => {
    updateTable(Setting.swapRow(tbl, i, i + 1));
  }, [updateTable]);

  const nameItems = [
    {name: "Signin methods", displayName: i18next.t("application:Signin methods")},
    {name: "Logo", displayName: i18next.t("general:Logo")},
    {name: "Back button", displayName: i18next.t("login:Back button")},
    {name: "Languages", displayName: i18next.t("general:Languages")},
    {name: "Username", displayName: i18next.t("signup:Username")},
    {name: "Password", displayName: i18next.t("general:Password")},
    {name: "Verification code", displayName: i18next.t("login:Verification code")},
    {name: "Providers", displayName: i18next.t("application:Providers")},
    {name: "Agreement", displayName: i18next.t("signup:Agreement")},
    {name: "Forgot password?", displayName: i18next.t("login:Forgot password?")},
    {name: "Login button", displayName: i18next.t("login:Signin button")},
    {name: "Signup link", displayName: i18next.t("general:Signup link")},
    {name: "Captcha", displayName: i18next.t("general:Captcha")},
    {name: "Auto sign in", displayName: i18next.t("login:Auto sign in")},
    {name: "Select organization", displayName: i18next.t("login:Select organization")},
  ];

  const getItemDisplayName = (text) => {
    const item = nameItems.filter(item => item.name === text);
    if (item.length === 0) {return "";}
    return item[0].displayName;
  };

  const getRuleOptions = (record) => {
    if (record.name === "Providers") {
      return [{id: "big", name: i18next.t("application:Big icon")}, {id: "small", name: i18next.t("application:Small icon")}];
    }
    if (record.name === "Captcha") {
      return [{id: "pop up", name: i18next.t("application:Pop up")}, {id: "inline", name: i18next.t("application:Inline")}];
    }
    if (record.name === "Forgot password?") {
      return [
        {id: "None", name: `${i18next.t("login:Auto sign in")} - ${i18next.t("general:True")}`},
        {id: "Auto sign in - False", name: `${i18next.t("login:Auto sign in")} - ${i18next.t("general:False")}`},
      ];
    }
    return [];
  };

  return (
    <div className="mt-5">
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <span className="text-sm text-gray-300">{title}</span>
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => addRow(table)}>
            {i18next.t("general:Add")}
          </button>
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => addCustomRow(table)}>
            {i18next.t("general:Add custom item")}
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("organization:Visible")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("signup:Label")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("application:Custom CSS")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("signup:Placeholder")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "155px"}}>{i18next.t("application:Rule")}</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {table.map((row, i) => {
                const ruleOptions = getRuleOptions(row);
                const showLabel = row.name.startsWith("Text ") || row?.isCustom || ["Username", "Password", "Verification code", "Signup link", "Forgot password?", "Login button"].includes(row.name);
                const showCustomCss = !row.name.startsWith("Text ") && !row?.isCustom;
                const showPlaceholder = row.name === "Username" || row.name === "Password";

                return (
                  <tr key={row.name} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                    <td className="px-4 py-2">
                      {row.isCustom ? (
                        <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white opacity-50" value={row.name || ""} disabled />
                      ) : (
                        <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.name || ""} onChange={e => {
                          updateField(table, i, "name", e.target.value);
                          updateField(table, i, "customCss", SigninTableDefaultCssMap[e.target.value]);
                        }}>
                          <option value="">{getItemDisplayName(row.name) || "--"}</option>
                          {Setting.getDeduplicatedArray(nameItems, table, "name").map((item, idx) => (
                            <option key={idx} value={item.name}>{item.displayName}</option>
                          ))}
                        </select>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      {row.name !== "ID" ? (
                        <input type="checkbox" className="rounded bg-white/5 border-white/10 text-blue-500" checked={!!row.visible} onChange={e => {
                          updateField(table, i, "visible", e.target.checked);
                          if (!e.target.checked) {updateField(table, i, "required", false);} else {updateField(table, i, "required", true);}
                        }} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      {showLabel ? (
                        <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={(row.name.startsWith("Text ") || row?.isCustom) ? (row.customCss || "") : (row.label || "")} onChange={e => {
                          if (row.name.startsWith("Text ") || row?.isCustom) {
                            updateField(table, i, "customCss", e.target.value);
                          } else {
                            updateField(table, i, "label", e.target.value);
                          }
                        }} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      {showCustomCss ? (
                        <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={(row.customCss || "").replaceAll("<style>", "").replaceAll("</style>", "")} onChange={e => updateField(table, i, "customCss", e.target.value)} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      {showPlaceholder ? (
                        <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.placeholder || ""} onChange={e => updateField(table, i, "placeholder", e.target.value)} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      {ruleOptions.length > 0 ? (
                        <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.rule || ""} onChange={e => updateField(table, i, "rule", e.target.value)}>
                          {ruleOptions.map(opt => (
                            <option key={opt.id} value={opt.id}>{opt.name}</option>
                          ))}
                        </select>
                      ) : null}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button title={i18next.t("general:Up")} disabled={i === 0} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => upRow(table, i)}>
                          <ArrowUp className="w-4 h-4" />
                        </button>
                        <button title={i18next.t("general:Down")} disabled={i === table.length - 1} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => downRow(table, i)}>
                          <ArrowDown className="w-4 h-4" />
                        </button>
                        <button title={i18next.t("general:Delete")} className="p-1 rounded hover:bg-white/10 text-red-400 hover:text-red-300" onClick={() => deleteRow(table, i)}>
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default SigninTable;

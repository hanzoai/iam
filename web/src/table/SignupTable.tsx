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
import React, {useCallback} from "react";
import {ArrowDown, ArrowUp, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import i18next from "i18next";
import Editor from "../common/Editor";

const EmailCss = ".signup-email{}\n.signup-email-input{}\n.signup-email-code{}\n.signup-email-code-input{}\n";
const PhoneCss = ".signup-phone{}\n.signup-phone-input{}\n.phone-code{}\n.signup-phone-code-input{}";

export const SignupTableDefaultCssMap = {
  "Username": ".signup-username {}\n.signup-username-input {}",
  "Display name": ".signup-first-name {}\n.signup-first-name-input{}\n.signup-last-name{}\n.signup-last-name-input{}\n.signup-name{}\n.signup-name-input{}",
  "Affiliation": ".signup-affiliation{}\n.signup-affiliation-input{}",
  "Country/Region": ".signup-country-region{}\n.signup-region-select{}",
  "ID card": ".signup-idcard{}\n.signup-idcard-input{}",
  "Password": ".signup-password{}\n.signup-password-input{}",
  "Confirm password": ".signup-confirm{}",
  "Email": EmailCss,
  "Phone": PhoneCss,
  "Email or Phone": EmailCss + PhoneCss,
  "Phone or Email": EmailCss + PhoneCss,
  "Invitation code": ".signup-invitation-code{}\n.signup-invitation-code-input{}",
  "Agreement": ".login-agreement{}",
  "Signup button": ".signup-button{}\n.signup-link{}",
  "Providers": ".provider-img {\n width: 30px;\n margin: 5px;\n }\n .provider-big-img {\n margin-bottom: 10px;\n }\n ",
};

function SignupTable({title, table, onUpdateTable}) {
  const updateTable = useCallback((tbl) => {
    onUpdateTable(tbl);
  }, [onUpdateTable]);

  const updateField = useCallback((tbl, index, key, value) => {
    tbl[index][key] = value;
    updateTable([...tbl]);
  }, [updateTable]);

  const addRow = useCallback((tbl) => {
    const row = {name: Setting.getNewRowNameForTable(tbl, "Please select a signup item"), visible: true, required: true, options: [], rule: "None", customCss: ""};
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
    {name: "Username", displayName: i18next.t("signup:Username")},
    {name: "ID", displayName: i18next.t("general:ID")},
    {name: "Display name", displayName: i18next.t("general:Display name")},
    {name: "First name", displayName: i18next.t("general:First name")},
    {name: "Last name", displayName: i18next.t("general:Last name")},
    {name: "Affiliation", displayName: i18next.t("user:Affiliation")},
    {name: "Gender", displayName: i18next.t("user:Gender")},
    {name: "Bio", displayName: i18next.t("user:Bio")},
    {name: "Tag", displayName: i18next.t("user:Tag")},
    {name: "Education", displayName: i18next.t("user:Education")},
    {name: "Country/Region", displayName: i18next.t("user:Country/Region")},
    {name: "ID card", displayName: i18next.t("user:ID card")},
    {name: "Password", displayName: i18next.t("general:Password")},
    {name: "Confirm password", displayName: i18next.t("general:Confirm")},
    {name: "Email", displayName: i18next.t("general:Email")},
    {name: "Phone", displayName: i18next.t("general:Phone")},
    {name: "Email or Phone", displayName: i18next.t("general:Email or Phone")},
    {name: "Phone or Email", displayName: i18next.t("general:Phone or Email")},
    {name: "Invitation code", displayName: i18next.t("application:Invitation code")},
    {name: "Agreement", displayName: i18next.t("signup:Agreement")},
    {name: "Signup button", displayName: i18next.t("signup:Signup button")},
    {name: "Providers", displayName: i18next.t("application:Providers")},
    {name: "Text 1", displayName: i18next.t("signup:Text 1")},
    {name: "Text 2", displayName: i18next.t("signup:Text 2")},
    {name: "Text 3", displayName: i18next.t("signup:Text 3")},
    {name: "Text 4", displayName: i18next.t("signup:Text 4")},
    {name: "Text 5", displayName: i18next.t("signup:Text 5")},
  ];

  const getItemDisplayName = (text) => {
    const item = nameItems.filter(item => item.name === text);
    if (item.length === 0) {return "";}
    return item[0].displayName;
  };

  const getRuleOptions = (record) => {
    if (record.name === "ID") {
      return [{id: "Random", name: i18next.t("application:Random")}, {id: "Incremental", name: i18next.t("application:Incremental")}];
    } else if (record.name === "Display name") {
      return [{id: "None", name: i18next.t("general:None")}, {id: "Real name", name: i18next.t("application:Real name")}, {id: "First, last", name: i18next.t("application:First, last")}];
    } else if (record.name === "Email") {
      return [{id: "Normal", name: i18next.t("application:Normal")}, {id: "No verification", name: i18next.t("application:No verification")}];
    } else if (record.name === "Phone") {
      return [{id: "Normal", name: i18next.t("application:Normal")}, {id: "No verification", name: i18next.t("application:No verification")}];
    } else if (record.name === "Agreement") {
      return [{id: "None", name: i18next.t("application:Only signup")}, {id: "Signin", name: i18next.t("application:Signin")}, {id: "Signin (Default True)", name: i18next.t("application:Signin (Default True)")}];
    } else if (record.name === "Providers") {
      return [{id: "big", name: i18next.t("application:Big icon")}, {id: "small", name: i18next.t("application:Small icon")}];
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
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "80px"}}>{i18next.t("organization:Visible")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "80px"}}>{i18next.t("organization:Required")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "80px"}}>{i18next.t("provider:Prompted")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "160px"}}>{i18next.t("general:Type")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "150px"}}>{i18next.t("signup:Label")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "180px"}}>{i18next.t("application:Custom CSS")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "110px"}}>{i18next.t("signup:Placeholder")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "180px"}}>{i18next.t("signup:Options")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "180px"}}>{i18next.t("signup:Regex")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "155px"}}>{i18next.t("application:Rule")}</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {table.map((row, i) => {
                const ruleOptions = getRuleOptions(row);
                const showRequired = row.visible && !["Signup button", "Providers"].includes(row.name);
                const showPrompted = !["ID", "Signup button", "Providers"].includes(row.name) && !(row.visible && row.name !== "Country/Region");
                const showPlaceholder = !row.name.startsWith("Text ");
                const showRegex = !row.name.startsWith("Text ") && !["Password", "Confirm password", "Signup button", "Provider"].includes(row.name);
                const showOptions = row.type === "Single Choice" || row.type === "Multiple Choices";

                return (
                  <tr key={row.name} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                    <td className="px-4 py-2">
                      <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.name || ""} onChange={e => {
                        updateField(table, i, "name", e.target.value);
                        updateField(table, i, "customCss", SignupTableDefaultCssMap[e.target.value]);
                      }}>
                        <option value="">{getItemDisplayName(row.name) || "--"}</option>
                        {Setting.getDeduplicatedArray(nameItems, table, "name").map((item, idx) => (
                          <option key={idx} value={item.name}>{item.displayName}</option>
                        ))}
                      </select>
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
                      {showRequired ? (
                        <input type="checkbox" className="rounded bg-white/5 border-white/10 text-blue-500" checked={!!row.required} disabled={row.name === "Password"} onChange={e => updateField(table, i, "required", e.target.checked)} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      {showPrompted ? (
                        <input type="checkbox" className="rounded bg-white/5 border-white/10 text-blue-500" checked={!!row.prompted} onChange={e => updateField(table, i, "prompted", e.target.checked)} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.type || ""} onChange={e => updateField(table, i, "type", e.target.value)}>
                        <option value="Input">{i18next.t("application:Input")}</option>
                        <option value="Single Choice">{i18next.t("application:Single Choice")}</option>
                        <option value="Multiple Choices">{i18next.t("application:Multiple Choices")}</option>
                      </select>
                    </td>
                    <td className="px-4 py-2">
                      <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.label || ""} onChange={e => updateField(table, i, "label", e.target.value)} />
                    </td>
                    <td className="px-4 py-2">
                      <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.customCss || SignupTableDefaultCssMap[row.name] || ""} onChange={e => updateField(table, i, "customCss", e.target.value || SignupTableDefaultCssMap[row.name])} />
                    </td>
                    <td className="px-4 py-2">
                      {showPlaceholder ? (
                        <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.placeholder || ""} onChange={e => updateField(table, i, "placeholder", e.target.value)} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      {showOptions ? (
                        <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" placeholder="comma-separated" value={(row.options || []).join(", ")} onChange={e => updateField(table, i, "options", e.target.value.split(",").map(s => s.trim()).filter(Boolean))} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      {showRegex ? (
                        <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.regex || ""} onChange={e => updateField(table, i, "regex", e.target.value)} />
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
                        <button title={i18next.t("general:Delete")} disabled={row.name === "Signup button"} className="p-1 rounded hover:bg-white/10 text-red-400 hover:text-red-300 disabled:opacity-30" onClick={() => deleteRow(table, i)}>
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

export default SignupTable;

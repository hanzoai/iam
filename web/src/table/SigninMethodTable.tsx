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

// @ts-nocheck
import React, {useCallback} from "react";
import {ArrowDown, ArrowUp, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import i18next from "i18next";

function SigninMethodTable({title, table, onUpdateTable}) {
  const updateTable = useCallback((tbl) => {
    onUpdateTable(tbl);
  }, [onUpdateTable]);

  const updateField = useCallback((tbl, index, key, value) => {
    tbl[index][key] = value;
    updateTable([...tbl]);
  }, [updateTable]);

  const items = [
    {name: "Password", displayName: i18next.t("general:Password")},
    {name: "Verification code", displayName: i18next.t("login:Verification code")},
    {name: "WebAuthn", displayName: i18next.t("login:WebAuthn")},
    {name: "LDAP", displayName: i18next.t("login:LDAP")},
    {name: "Face ID", displayName: i18next.t("login:Face ID")},
    {name: "WeChat", displayName: i18next.t("login:WeChat")},
  ];

  const addRow = useCallback((tbl) => {
    const row = {name: Setting.getNewRowNameForTable(tbl, "Please select a signin method"), displayName: "", rule: "None"};
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

  const getItemDisplayName = (text) => {
    const item = items.filter(item => item.name === text);
    if (item.length === 0) {return "";}
    return item[0].displayName;
  };

  const getRuleOptions = (record) => {
    if (record.name === "Verification code") {
      return [
        {id: "All", name: i18next.t("general:All")},
        {id: "Email only", name: i18next.t("general:Email only")},
        {id: "Phone only", name: i18next.t("general:Phone only")},
      ];
    } else if (record.name === "Password") {
      return [
        {id: "All", name: i18next.t("general:All")},
        {id: "Non-LDAP", name: i18next.t("general:Non-LDAP")},
        {id: "Hide password", name: i18next.t("general:Hide password")},
      ];
    } else if (record.name === "WeChat") {
      return [
        {id: "Tab", name: i18next.t("general:Tab")},
        {id: "Login page", name: i18next.t("general:Login page")},
      ];
    }
    return [];
  };

  return (
    <div className="mt-5">
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <span className="text-sm text-gray-300">{title}</span>
          <button
            className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
            disabled={Setting.getDeduplicatedArray(items, table, "name").length === 0}
            onClick={() => addRow(table)}
          >
            {i18next.t("general:Add")}
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "300px"}}>{i18next.t("general:Display name")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "155px"}}>{i18next.t("application:Rule")}</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {table.map((row, i) => {
                const ruleOptions = getRuleOptions(row);
                return (
                  <tr key={row.name} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                    <td className="px-4 py-2">
                      <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.name || ""} onChange={e => {
                        const value = e.target.value;
                        updateField(table, i, "name", value);
                        updateField(table, i, "displayName", value);
                        if (value === "Verification code" || value === "Password") {
                          updateField(table, i, "rule", "All");
                        } else if (value === "WeChat") {
                          updateField(table, i, "rule", "Tab");
                        } else {
                          updateField(table, i, "rule", "None");
                        }
                      }}>
                        <option value="">{getItemDisplayName(row.name) || "--"}</option>
                        {Setting.getDeduplicatedArray(items, table, "name").map((item, idx) => (
                          <option key={idx} value={item.name}>{item.displayName}</option>
                        ))}
                      </select>
                    </td>
                    <td className="px-4 py-2">
                      <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.displayName || ""} onChange={e => updateField(table, i, "displayName", e.target.value)} />
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
                        <button title={i18next.t("general:Delete")} disabled={table.length <= 1} className="p-1 rounded hover:bg-white/10 text-red-400 hover:text-red-300 disabled:opacity-30" onClick={() => deleteRow(table, i)}>
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

export default SigninMethodTable;

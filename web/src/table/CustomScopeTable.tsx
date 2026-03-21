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
import React, {useCallback} from "react";
import {ArrowDown, ArrowUp, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import i18next from "i18next";

const DefaultScopes = [
  {scope: "openid", displayName: "OpenID", description: "Authenticate the user and obtain an ID token"},
  {scope: "profile", displayName: "Profile", description: "Read all user profile data"},
  {scope: "email", displayName: "Email", description: "Access user email addresses (read-only)"},
  {scope: "address", displayName: "Address", description: "Access the user's address information"},
  {scope: "phone", displayName: "Phone", description: "Access the user's phone number information"},
  {scope: "offline_access", displayName: "Offline Access", description: "Obtain refresh tokens for offline access"},
];

function CustomScopeTable({title, table: rawTable, onUpdateTable}) {
  const table = rawTable || [];

  const normalizeScope = (scope) => (scope || "").trim().toLowerCase();

  const getAvailableDefaultScopes = useCallback((tbl) => {
    const existingScopes = new Set((tbl || []).map(item => normalizeScope(item?.scope)).filter(Boolean));
    return DefaultScopes.filter(item => !existingScopes.has(normalizeScope(item.scope)));
  }, []);

  const isScopeMissing = (row) => {
    if (!row) {return true;}
    return (row.scope || "").trim() === "";
  };

  const updateTable = useCallback((tbl) => {
    onUpdateTable(tbl);
  }, [onUpdateTable]);

  const updateField = useCallback((tbl, index, key, value) => {
    tbl[index][key] = value;
    updateTable([...tbl]);
  }, [updateTable]);

  const addRow = useCallback((tbl) => {
    const row = {scope: "", displayName: "", description: ""};
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

  return (
    <div className="mt-5">
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center justify-between">
          <span className="text-sm text-gray-300">{title}</span>
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => addRow(table)}>
            {i18next.t("general:Add")}
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10 bg-white/[0.02]">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "260px"}}>
                <span className="text-red-400">*</span> {i18next.t("general:Name")}
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("general:Display name")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Description")}</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "110px"}}>{i18next.t("general:Action")}</th>
            </tr>
          </thead>
          <tbody>
            {table.map((row, i) => {
              const availableDefaultScopes = getAvailableDefaultScopes(table);
              return (
                <tr key={row.scope?.trim() || `temp_${i}`} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                  <td className="px-4 py-2">
                    <input
                      list={`scope-options-${i}`}
                      className={`w-full bg-white/5 border rounded px-2 py-1 text-sm text-white ${isScopeMissing(row) ? "border-red-500" : "border-white/10"}`}
                      value={row.scope || ""}
                      placeholder="Select or input scope"
                      onChange={e => {
                        updateField(table, i, "scope", e.target.value);
                        const selected = availableDefaultScopes.find(item => item.scope === e.target.value);
                        if (selected) {
                          updateField(table, i, "displayName", selected.displayName);
                          updateField(table, i, "description", selected.description);
                        }
                      }}
                    />
                    <datalist id={`scope-options-${i}`}>
                      {availableDefaultScopes.map(item => (
                        <option key={item.scope} value={item.scope}>{item.scope}</option>
                      ))}
                    </datalist>
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.displayName || ""} onChange={e => updateField(table, i, "displayName", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.description || ""} onChange={e => updateField(table, i, "description", e.target.value)} />
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
  );
}

export default CustomScopeTable;

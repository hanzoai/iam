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
import React, {useCallback, useRef} from "react";
import {ArrowDown, ArrowUp, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import i18next from "i18next";

const samlVariables = [
  "$user.owner", "$user.name", "$user.email", "$user.id",
  "$user.phone", "$user.roles", "$user.permissions", "$user.groups",
];

const nameFormatOptions = [
  {key: "Unspecified", value: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified", label: "Unspecified"},
  {key: "Basic", value: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", label: "Basic"},
  {key: "UriReference", value: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", label: "UriReference"},
  {key: "x500AttributeName", value: "urn:oasis:names:tc:SAML:2.0:attrname-format:X500", label: "x500AttributeName"},
];

function SamlAttributeTable({table, onUpdateTable}) {
  const updateTable = useCallback((tbl) => {
    onUpdateTable(tbl);
  }, [onUpdateTable]);

  const updateField = useCallback((tbl, index, key, value) => {
    tbl[index][key] = value;
    updateTable([...tbl]);
  }, [updateTable]);

  const addRow = useCallback((tbl) => {
    const row = {Name: "", nameFormat: "", value: ""};
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
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02]">
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => addRow(table)}>
            {i18next.t("general:Add")}
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10 bg-white/[0.02]">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("general:Name")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("general:Name format")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("webhook:Value")}</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
            </tr>
          </thead>
          <tbody>
            {(table || []).map((row, i) => (
              <tr key={i} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                <td className="px-4 py-2">
                  <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.name || ""} onChange={e => updateField(table, i, "name", e.target.value)} />
                </td>
                <td className="px-4 py-2">
                  <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.nameFormat || "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"} onChange={e => updateField(table, i, "nameFormat", e.target.value)}>
                    {nameFormatOptions.map(opt => (
                      <option key={opt.key} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                </td>
                <td className="px-4 py-2">
                  <input
                    list={`saml-vars-${i}`}
                    className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white"
                    value={row.value || ""}
                    onChange={e => updateField(table, i, "value", e.target.value)}
                  />
                  <datalist id={`saml-vars-${i}`}>
                    {samlVariables.map(v => <option key={v} value={v} />)}
                  </datalist>
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
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default SamlAttributeTable;

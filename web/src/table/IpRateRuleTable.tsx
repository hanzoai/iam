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
import i18next from "i18next";

const defaultRules = [
  {name: "Default IP Rate", operator: "100", value: "6000"},
];

function IpRateRuleTable({title, table, onUpdateTable}) {
  const updateTable = useCallback((tbl) => {
    onUpdateTable(tbl);
  }, [onUpdateTable]);

  const updateField = useCallback((tbl, index, key, value) => {
    tbl[index][key] = String(value);
    updateTable([...tbl]);
  }, [updateTable]);

  const restore = useCallback(() => {
    updateTable(defaultRules);
  }, [updateTable]);

  if (table.length === 0) {
    updateTable(defaultRules);
  }

  return (
    <div className="mt-5">
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <span className="text-sm text-gray-300">{title}</span>
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => restore()}>
            {i18next.t("general:Restore")}
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10 bg-white/[0.02]">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "20%"}}>{i18next.t("general:Name")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "40%"}}>{i18next.t("rule:Rate")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("rule:Block Duration")}</th>
            </tr>
          </thead>
          <tbody>
            {table.map((row, i) => (
              <tr key={i} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                <td className="px-4 py-2">
                  <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.name || ""} onChange={e => updateField(table, i, "name", e.target.value)} />
                </td>
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2">
                    <input type="number" className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={Number(row.operator)} onChange={e => updateField(table, i, "operator", e.target.value)} />
                    <span className="text-xs text-gray-400 whitespace-nowrap">requests / ip / s</span>
                  </div>
                </td>
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2">
                    <input type="number" className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={Number(row.value)} onChange={e => updateField(table, i, "value", e.target.value)} />
                    <span className="text-xs text-gray-400 whitespace-nowrap">{i18next.t("usage:seconds")}</span>
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

export default IpRateRuleTable;

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
import React, {useCallback, useRef, useState} from "react";
import {ArrowDown, ArrowUp, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import i18next from "i18next";
import RegionSelect from "../common/select/RegionSelect";

const TAG_OPTIONS = [
  {value: "Home", label: "Home"},
  {value: "Work", label: "Work"},
  {value: "Other", label: "Other"},
];

function AddressTable({title, table, onUpdateTable}) {
  const [addresses, setAddresses] = useState(() =>
    table !== null ? table.map((item, index) => ({...item, key: index})) : []
  );
  const countRef = useRef(table?.length ?? 0);

  const updateTable = useCallback((newTable) => {
    setAddresses(newTable);
    onUpdateTable([...newTable].map((item) => {
      const newItem = Setting.deepCopy(item);
      delete newItem.key;
      return newItem;
    }));
  }, [onUpdateTable]);

  const updateField = useCallback((tbl, index, key, value) => {
    tbl[index][key] = value;
    updateTable([...tbl]);
  }, [updateTable]);

  const addRow = useCallback((tbl) => {
    const row = {key: countRef.current, tag: "", line1: "", line2: "", city: "", state: "", zipCode: "", region: ""};
    let newTable = tbl ?? [];
    countRef.current += 1;
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

  const getTagOptions = () => TAG_OPTIONS.map(opt => ({
    ...opt,
    label: opt.value === "Home" ? i18next.t("general:Home") : opt.value === "Work" ? i18next.t("user:Work") : i18next.t("user:Other"),
  }));

  return (
    <div className="mt-5">
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <span className="text-sm text-gray-300">{title}</span>
          <button
            className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white"
            onClick={() => addRow(addresses)}
          >
            {i18next.t("general:Add")}
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("user:Tag")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "150px"}}>{i18next.t("user:Line 1")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "150px"}}>{i18next.t("user:Line 2")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("user:City")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:State")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("user:Zip code")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "150px"}}>{i18next.t("provider:Region")}</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {addresses.map((row, i) => (
                <tr key={row.key} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                  <td className="px-4 py-2">
                    <input
                      list={`tag-options-${i}`}
                      className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white"
                      value={row.tag || ""}
                      onChange={e => updateField(addresses, i, "tag", e.target.value)}
                    />
                    <datalist id={`tag-options-${i}`}>
                      {getTagOptions().map(opt => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </datalist>
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.line1 || ""} onChange={e => updateField(addresses, i, "line1", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.line2 || ""} onChange={e => updateField(addresses, i, "line2", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.city || ""} onChange={e => updateField(addresses, i, "city", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.state || ""} onChange={e => updateField(addresses, i, "state", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.zipCode || ""} onChange={e => updateField(addresses, i, "zipCode", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <RegionSelect size="small" value={row.region} onChange={value => updateField(addresses, i, "region", value)} />
                  </td>
                  <td className="px-4 py-2 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button title={i18next.t("general:Up")} disabled={i === 0} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => upRow(addresses, i)}>
                        <ArrowUp className="w-4 h-4" />
                      </button>
                      <button title={i18next.t("general:Down")} disabled={i === addresses.length - 1} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => downRow(addresses, i)}>
                        <ArrowDown className="w-4 h-4" />
                      </button>
                      <button title={i18next.t("general:Delete")} className="p-1 rounded hover:bg-white/10 text-red-400 hover:text-red-300" onClick={() => deleteRow(addresses, i)}>
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
    </div>
  );
}

export default AddressTable;

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
import React, {useCallback, useRef, useState} from "react";
import {ArrowDown, ArrowUp, Trash2} from "lucide-react";
import * as Setting from "../Setting";
import i18next from "i18next";
import {IamAppQrCode, IamAppUrl} from "../common/IamAppConnector";

function MfaAccountTable({title, table, icon, accessToken, onUpdateTable}) {
  const [mfaAccounts, setMfaAccounts] = useState(() =>
    table !== null ? table.map((item, index) => ({...item, key: index})) : []
  );
  const [showQrCode, setShowQrCode] = useState(false);
  const [showUrl, setShowUrl] = useState(false);
  const countRef = useRef(table?.length ?? 0);

  const updateTable = useCallback((newTable) => {
    setMfaAccounts(newTable);
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
    const row = {key: countRef.current, accountName: "", issuer: "", secretKey: ""};
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

  return (
    <div className="mt-5">
      <div className="border border-white/10 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02] flex items-center gap-4">
          <span className="text-sm text-gray-300">{title}</span>
          <button className="px-3 py-1 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white" onClick={() => addRow(mfaAccounts)}>
            {i18next.t("general:Add")}
          </button>
          <div className="relative">
            <button className="px-3 py-1 text-xs font-medium rounded bg-white/10 hover:bg-white/20 text-white" onClick={() => setShowQrCode(!showQrCode)}>
              {i18next.t("general:QR Code")}
            </button>
            {showQrCode && (
              <div className="absolute top-full left-0 mt-1 z-10">
                <IamAppQrCode accessToken={accessToken} icon={icon} />
              </div>
            )}
          </div>
          <div className="relative">
            <button className="px-3 py-1 text-xs font-medium rounded bg-white/10 hover:bg-white/20 text-white" onClick={() => setShowUrl(!showUrl)}>
              {i18next.t("general:URL")}
            </button>
            {showUrl && (
              <div className="absolute top-full left-0 mt-1 z-10">
                <IamAppUrl accessToken={accessToken} />
              </div>
            )}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "400px"}}>{i18next.t("forget:Account")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "300px"}}>Issuer</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Origin</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("provider:Secret key")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "60px"}}>{i18next.t("general:Logo")}</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {mfaAccounts.map((row, i) => (
                <tr key={row.key} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.accountName || ""} onChange={e => updateField(mfaAccounts, i, "accountName", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.issuer || ""} onChange={e => updateField(mfaAccounts, i, "issuer", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.origin || ""} onChange={e => updateField(mfaAccounts, i, "origin", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    <input type="password" className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.secretKey || ""} onChange={e => updateField(mfaAccounts, i, "secretKey", e.target.value)} />
                  </td>
                  <td className="px-4 py-2">
                    {row.issuer ? (
                      <img width={36} height={36} src={`${Setting.StaticBaseUrl}/img/social_${row.issuer.toLowerCase()}.png`} onError={e => { e.target.src = `${Setting.StaticBaseUrl}/img/social_default.png`; }} alt={row.issuer} />
                    ) : (
                      <img width={36} height={36} src={`${Setting.StaticBaseUrl}/img/social_default.png`} alt="default" />
                    )}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button title={i18next.t("general:Up")} disabled={i === 0} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => upRow(mfaAccounts, i)}>
                        <ArrowUp className="w-4 h-4" />
                      </button>
                      <button title={i18next.t("general:Down")} disabled={i === mfaAccounts.length - 1} className="p-1 rounded hover:bg-white/10 text-gray-400 hover:text-white disabled:opacity-30" onClick={() => downRow(mfaAccounts, i)}>
                        <ArrowDown className="w-4 h-4" />
                      </button>
                      <button title={i18next.t("general:Delete")} className="p-1 rounded hover:bg-white/10 text-red-400 hover:text-red-300" onClick={() => deleteRow(mfaAccounts, i)}>
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

export default MfaAccountTable;

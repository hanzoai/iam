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
import React, {useCallback, useState} from "react";
import * as Setting from "../Setting";
import i18next from "i18next";
import * as ConsentBackend from "../backend/ConsentBackend";

function ConsentTable({title, table, onUpdateTable}) {
  const [confirmingScope, setConfirmingScope] = useState(null);
  const [confirmingRow, setConfirmingRow] = useState(null);

  const deleteScope = useCallback((record, scopeToDelete) => {
    ConsentBackend.revokeConsent({
      application: record.application,
      grantedScopes: scopeToDelete ? [scopeToDelete] : record.grantedScopes,
    })
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully revoked"));
          onUpdateTable();
        } else {
          Setting.showMessage("error", res.msg);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
    setConfirmingScope(null);
    setConfirmingRow(null);
  }, [onUpdateTable]);

  return (
    <div className="border border-white/10 rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-white/10 bg-white/[0.02]">
        <span className="text-sm text-gray-300">{title}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10 bg-white/[0.02]">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "200px"}}>{i18next.t("general:Application")}</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("consent:Granted scopes")}</th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
            </tr>
          </thead>
          <tbody>
            {(table || []).map((row, i) => (
              <tr key={row.application} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                <td className="px-4 py-2 text-white">{row.application}</td>
                <td className="px-4 py-2">
                  <div className="flex flex-wrap gap-1">
                    {(Array.isArray(row.grantedScopes) ? row.grantedScopes : []).map((scope, idx) => (
                      <span
                        key={idx}
                        className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-500/20 text-blue-300 cursor-pointer hover:bg-blue-500/30"
                        onClick={() => {
                          if (confirmingScope === `${row.application}-${scope}`) {
                            deleteScope(row, scope);
                          } else {
                            setConfirmingScope(`${row.application}-${scope}`);
                            setConfirmingRow(null);
                          }
                        }}
                      >
                        {confirmingScope === `${row.application}-${scope}` ? `Revoke ${scope}?` : scope}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-2 text-right">
                  {confirmingRow === row.application ? (
                    <div className="flex items-center justify-end gap-1">
                      <button className="px-2 py-1 text-xs font-medium rounded bg-red-600 hover:bg-red-500 text-white" onClick={() => deleteScope(row)}>
                        {i18next.t("general:OK")}
                      </button>
                      <button className="px-2 py-1 text-xs font-medium rounded bg-white/10 hover:bg-white/20 text-white" onClick={() => setConfirmingRow(null)}>
                        {i18next.t("general:Cancel")}
                      </button>
                    </div>
                  ) : (
                    <button
                      className="px-3 py-1 text-xs font-medium rounded bg-red-600 hover:bg-red-500 text-white"
                      onClick={() => {
                        setConfirmingRow(row.application);
                        setConfirmingScope(null);
                      }}
                    >
                      {i18next.t("consent:Delete")}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default ConsentTable;

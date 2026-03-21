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
import {CountryCodeSelect} from "../common/select/CountryCodeSelect";
import * as Setting from "../Setting";
import i18next from "i18next";
import * as Provider from "../auth/Provider";

function ProviderTable({title, table, providers, application, onUpdateTable}) {
  const getUserOrganization = () => application?.organizationObj;

  const updateTable = useCallback((tbl) => {
    onUpdateTable(tbl);
  }, [onUpdateTable]);

  const updateField = useCallback((tbl, index, key, value) => {
    tbl[index][key] = value;
    updateTable([...tbl]);
  }, [updateTable]);

  const addRow = useCallback((tbl) => {
    const row = {name: Setting.getNewRowNameForTable(tbl, "Please select a provider"), canSignUp: true, canSignIn: true, canUnlink: true, prompted: false, signupGroup: "", rule: "None"};
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

  const isOAuthSamlWeb3 = (record) => ["OAuth", "Web3", "SAML"].includes(record.provider?.category);

  const getRuleContent = (row, i) => {
    if (row.provider?.type === "Google") {
      const text = row.rule === "None" ? "Default" : row.rule;
      return (
        <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={text} onChange={e => updateField(table, i, "rule", e.target.value)}>
          <option value="Default">{i18next.t("general:Default")}</option>
          <option value="OneTap">One Tap</option>
        </select>
      );
    } else if (row.provider?.category === "Captcha") {
      return (
        <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.rule || "None"} onChange={e => updateField(table, i, "rule", e.target.value)}>
          <option value="None">{i18next.t("general:None")}</option>
          <option value="Dynamic">{i18next.t("application:Dynamic")}</option>
          <option value="Always">{i18next.t("application:Always")}</option>
          <option value="Internet-Only">{i18next.t("application:Internet-Only")}</option>
        </select>
      );
    } else if (row.provider?.category === "SMS" || row.provider?.category === "Email") {
      const text = row.rule === "None" ? "All" : row.rule;
      return (
        <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={text} onChange={e => updateField(table, i, "rule", e.target.value)}>
          <option value="all">All</option>
          <option value="signup">Signup</option>
          <option value="login">Login</option>
          <option value="forget">Forget Password</option>
          <option value="reset">Reset Password</option>
          <option value="mfaSetup">Set MFA</option>
          <option value="mfaAuth">MFA Auth</option>
        </select>
      );
    }
    return null;
  };

  let showCanSignUp = application.enableSignUp;

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
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Category")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "80px"}}>{i18next.t("general:Type")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "140px"}}>{i18next.t("user:Country/Region")}</th>
                {showCanSignUp && <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("provider:Can signup")}</th>}
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("provider:Can signin")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("provider:Can unlink")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("provider:Prompted")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "120px"}}>{i18next.t("provider:Signup group")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase" style={{width: "160px"}}>{i18next.t("application:Rule")}</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase" style={{width: "100px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {table.map((row, i) => {
                const provider = Setting.getArrayItem(providers, "name", row.name);
                const owner = provider?.owner || getUserOrganization()?.name;
                const editUrl = provider && owner && provider.name ? `/providers/${owner}/${provider.name}` : null;

                return (
                  <tr key={row.name} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                    <td className="px-4 py-2">
                      <select className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.name || ""} onChange={e => {
                        const value = e.target.value;
                        updateField(table, i, "name", value);
                        const prov = Setting.getArrayItem(providers, "name", value);
                        updateField(table, i, "provider", prov);
                        if (prov?.category === "Email" || prov?.category === "SMS") {
                          updateField(table, i, "rule", "All");
                        }
                      }}>
                        <option value="">--</option>
                        {Setting.getDeduplicatedArray(providers, table, "name").map((prov, idx) => (
                          <option key={idx} value={prov.name}>{prov.displayName && prov.displayName !== prov.name ? `${prov.name} (${prov.displayName})` : prov.name}</option>
                        ))}
                      </select>
                    </td>
                    <td className="px-4 py-2 text-white">
                      {editUrl ? <a href={editUrl} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300">{provider?.category}</a> : provider?.category}
                    </td>
                    <td className="px-4 py-2">
                      {editUrl ? <a href={editUrl} target="_blank" rel="noopener noreferrer">{Provider.getProviderLogoWidget(provider, {disableLink: true})}</a> : Provider.getProviderLogoWidget(provider)}
                    </td>
                    <td className="px-4 py-2">
                      {row.provider?.category === "SMS" ? (
                        <CountryCodeSelect style={{width: "100%"}} hasDefault={true} mode="multiple" initValue={row.countryCodes || ["All"]} onChange={(value) => updateField(table, i, "countryCodes", value)} countryCodes={getUserOrganization()?.countryCodes} />
                      ) : null}
                    </td>
                    {showCanSignUp && (
                      <td className="px-4 py-2">
                        {isOAuthSamlWeb3(row) ? <input type="checkbox" className="rounded bg-white/5 border-white/10 text-blue-500" checked={!!row.canSignUp} onChange={e => updateField(table, i, "canSignUp", e.target.checked)} /> : null}
                      </td>
                    )}
                    <td className="px-4 py-2">
                      {isOAuthSamlWeb3(row) ? <input type="checkbox" className="rounded bg-white/5 border-white/10 text-blue-500" checked={!!row.canSignIn} onChange={e => updateField(table, i, "canSignIn", e.target.checked)} /> : null}
                    </td>
                    <td className="px-4 py-2">
                      {isOAuthSamlWeb3(row) ? <input type="checkbox" className="rounded bg-white/5 border-white/10 text-blue-500" checked={!!row.canUnlink} onChange={e => updateField(table, i, "canUnlink", e.target.checked)} /> : null}
                    </td>
                    <td className="px-4 py-2">
                      {isOAuthSamlWeb3(row) ? <input type="checkbox" className="rounded bg-white/5 border-white/10 text-blue-500" checked={!!row.prompted} onChange={e => updateField(table, i, "prompted", e.target.checked)} /> : null}
                    </td>
                    <td className="px-4 py-2">
                      {["OAuth", "Web3"].includes(row.provider?.category) ? (
                        <input className="w-full bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white" value={row.signupGroup || ""} onChange={e => updateField(table, i, "signupGroup", e.target.value)} />
                      ) : null}
                    </td>
                    <td className="px-4 py-2">{getRuleContent(row, i)}</td>
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

export default ProviderTable;

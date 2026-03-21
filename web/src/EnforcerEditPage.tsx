// @ts-nocheck
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

import React, {useEffect, useState} from "react";
import * as AdapterBackend from "./backend/AdapterBackend";
import * as EnforcerBackend from "./backend/EnforcerBackend";
import * as ModelBackend from "./backend/ModelBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import PolicyTable from "./table/PolicyTable";
import * as Setting from "./Setting";
import i18next from "i18next";
import {Button} from "./components/ui/button";

interface EnforcerEditPageProps { account: any; history: any; match: any; location: any; organizationName?: string; }

function EnforcerEditPage(props: EnforcerEditPageProps) {
  const {account, history, match, location} = props;
  const orgFromProps = props.organizationName ?? match.params.organizationName;
  const enforcerNameFromUrl = match.params.enforcerName;

  const [enforcerName, setEnforcerName] = useState(enforcerNameFromUrl);
  const [enforcer, setEnforcer] = useState<any>(null);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [models, setModels] = useState<any[]>([]);
  const [adapters, setAdapters] = useState<any[]>([]);
  const [mode] = useState(location.mode ?? "edit");

  useEffect(() => { getEnforcer(); getOrganizations(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function getEnforcer() {
    EnforcerBackend.getEnforcer(orgFromProps, enforcerNameFromUrl, true).then((res: any) => {
      if (res.data === null) { history.push("/404"); return; }
      if (res.status === "error") { Setting.showMessage("error", res.msg); return; }
      setEnforcer(res.data);
      getModels(orgFromProps);
      getAdapters(orgFromProps);
    });
  }

  function getOrganizations() { OrganizationBackend.getOrganizations("admin").then((res: any) => setOrganizations(res.data || [])); }
  function getModels(org: string) { ModelBackend.getModels(org).then((res: any) => setModels(res.data || [])); }
  function getAdapters(org: string) { AdapterBackend.getAdapters(org).then((res: any) => setAdapters(res.data || [])); }

  function updateField(key: string, value: any) { setEnforcer((prev: any) => ({...prev, [key]: value})); }

  function submitEdit(exitAfterSave: boolean) {
    const copy = Setting.deepCopy(enforcer);
    EnforcerBackend.updateEnforcer(orgFromProps, enforcerName, copy).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully saved"));
        setEnforcerName(enforcer.name);
        if (exitAfterSave) history.push("/enforcers");
        else history.push(`/enforcers/${enforcer.owner}/${enforcer.name}`);
      } else { Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`); updateField("name", enforcerName); }
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleDelete() {
    EnforcerBackend.deleteEnforcer(enforcer).then((res: any) => {
      if (res.status === "ok") history.push("/enforcers");
      else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  if (!enforcer) return null;
  const isBuiltIn = Setting.builtInObject(enforcer);

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("enforcer:New Enforcer") : i18next.t("enforcer:Edit Enforcer")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account) || isBuiltIn} value={enforcer.owner} onChange={e => { updateField("owner", e.target.value); getModels(e.target.value); getAdapters(e.target.value); }}>
              {organizations.map((org: any) => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={isBuiltIn} value={enforcer.name} onChange={e => updateField("name", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Display name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={enforcer.displayName} onChange={e => updateField("displayName", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Description")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={enforcer.description || ""} onChange={e => updateField("description", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Model")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={isBuiltIn} value={enforcer.model || ""} onChange={e => updateField("model", e.target.value)}>
              <option value="">-</option>
              {models.map((m: any) => <option key={`${m.owner}/${m.name}`} value={`${m.owner}/${m.name}`}>{m.owner}/{m.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Adapter")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={isBuiltIn} value={enforcer.adapter || ""} onChange={e => updateField("adapter", e.target.value)}>
              <option value="">-</option>
              {adapters.map((a: any) => <option key={`${a.owner}/${a.name}`} value={`${a.owner}/${a.name}`}>{a.owner}/{a.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("adapter:Policies")}</label>
            <div>
              <PolicyTable enforcer={enforcer} modelCfg={enforcer?.modelCfg} mode={mode} />
            </div>
          </div>
        </div>
      </div>
      <div className="flex gap-3 px-6">
        <Button variant="outline" size="lg" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
        <Button size="lg" onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
        {mode === "add" && <Button variant="outline" size="lg" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
      </div>
    </div>
  );
}

export default EnforcerEditPage;

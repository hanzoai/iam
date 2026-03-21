// @ts-nocheck
// Copyright 2022 The Hanzo Authors. All Rights Reserved.
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
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import {Button} from "./components/ui/button";

interface AdapterEditPageProps { account: any; history: any; match: any; location: any; organizationName?: string; }

function AdapterEditPage(props: AdapterEditPageProps) {
  const {account, history, match, location} = props;
  const orgFromProps = props.organizationName ?? match.params.organizationName;
  const adapterNameFromUrl = match.params.adapterName;

  const [adapterName, setAdapterName] = useState(adapterNameFromUrl);
  const [adapter, setAdapter] = useState<any>(null);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [mode] = useState(location.mode ?? "edit");

  useEffect(() => { getAdapter(); getOrganizations(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function getAdapter() {
    AdapterBackend.getAdapter(orgFromProps, adapterNameFromUrl).then((res: any) => {
      if (res.status === "ok") { if (res.data === null) { history.push("/404"); return; } setAdapter(res.data); }
    });
  }

  function getOrganizations() { OrganizationBackend.getOrganizations("admin").then((res: any) => setOrganizations(res.data || [])); }

  function updateField(key: string, value: any) { setAdapter((prev: any) => ({...prev, [key]: value})); }

  function submitEdit(exitAfterSave: boolean) {
    const copy = Setting.deepCopy(adapter);
    AdapterBackend.updateAdapter(orgFromProps, adapterName, copy).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully saved"));
        setAdapterName(adapter.name);
        if (exitAfterSave) history.push("/adapters");
        else history.push(`/adapters/${adapter.owner}/${adapter.name}`);
      } else { Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`); updateField("name", adapterName); }
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleDelete() {
    AdapterBackend.deleteAdapter(adapter).then((res: any) => {
      if (res.status === "ok") history.push("/adapters");
      else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function testConnection() {
    AdapterBackend.getPolicies("", "", `${adapter.owner}/${adapter.name}`).then((res: any) => {
      if (res.status === "ok") Setting.showMessage("success", i18next.t("syncer:Connect successfully"));
      else Setting.showMessage("error", i18next.t("syncer:Failed to connect") + ": " + res.msg);
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  if (!adapter) return null;
  const isBuiltIn = Setting.builtInObject(adapter);

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("adapter:New Adapter") : i18next.t("adapter:Edit Adapter")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account) || isBuiltIn} value={adapter.owner} onChange={e => updateField("owner", e.target.value)}>
              {organizations.map((org: any) => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={isBuiltIn} value={adapter.name} onChange={e => updateField("name", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("syncer:Table")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={isBuiltIn} value={adapter.table} onChange={e => updateField("table", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("adapter:Use same DB")}</label>
            <button disabled={isBuiltIn} className={`w-12 h-6 rounded-full transition-colors ${adapter.useSameDb || isBuiltIn ? "bg-primary" : "bg-zinc-700"}`} onClick={() => {
              const checked = !adapter.useSameDb;
              updateField("useSameDb", checked);
              if (checked) { updateField("type", ""); updateField("databaseType", ""); updateField("host", ""); updateField("port", 0); updateField("user", ""); updateField("password", ""); updateField("database", ""); }
              else { updateField("type", "Database"); updateField("databaseType", "mysql"); updateField("host", "localhost"); updateField("port", 3306); updateField("user", "root"); updateField("password", "123456"); updateField("database", "dbName"); }
            }}>
              <div className={`w-5 h-5 rounded-full bg-white transition-transform ${adapter.useSameDb || isBuiltIn ? "translate-x-6" : "translate-x-0.5"}`} />
            </button>
          </div>

          {!(adapter.useSameDb || isBuiltIn) && (
            <>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("general:Type")}</label>
                <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={adapter.type} onChange={e => updateField("type", e.target.value)}>
                  <option value="Database">Database</option>
                </select>
              </div>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("syncer:Database type")}</label>
                <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={adapter.databaseType} onChange={e => updateField("databaseType", e.target.value)}>
                  {[{id: "mysql", name: "MySQL"}, {id: "postgres", name: "PostgreSQL"}, {id: "mssql", name: "SQL Server"}, {id: "oracle", name: "Oracle"}, {id: "sqlite3", name: "Sqlite 3"}].map(db => <option key={db.id} value={db.id}>{db.name}</option>)}
                </select>
              </div>
              {[{label: i18next.t("provider:Host"), key: "host"}, {label: i18next.t("general:User"), key: "user"}, {label: i18next.t("general:Password"), key: "password"}, {label: i18next.t("syncer:Database"), key: "database"}].map(({label, key}) => (
                <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
                  <label className="text-sm text-zinc-400">{label}</label>
                  <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={adapter[key] || ""} onChange={e => updateField(key, e.target.value)} />
                </div>
              ))}
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("provider:Port")}</label>
                <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" min={0} max={65535} value={adapter.port} onChange={e => updateField("port", parseInt(e.target.value) || 0)} />
              </div>
            </>
          )}

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("provider:DB test")}</label>
            <Button disabled={orgFromProps !== adapter.owner} onClick={testConnection}>{i18next.t("syncer:Test DB Connection")}</Button>
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

export default AdapterEditPage;

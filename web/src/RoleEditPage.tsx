// @ts-nocheck
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

import React, {useEffect, useState} from "react";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as RoleBackend from "./backend/RoleBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import {Button} from "./components/ui/button";

interface RoleEditPageProps {
  account: any;
  history: any;
  match: any;
  location: any;
  organizationName?: string;
}

function RoleEditPage(props: RoleEditPageProps) {
  const {account, history, match, location} = props;
  const orgFromProps = props.organizationName ?? match.params.organizationName;
  const roleNameFromUrl = decodeURIComponent(match.params.roleName);

  const [roleName, setRoleName] = useState(roleNameFromUrl);
  const [role, setRole] = useState<any>(null);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [mode] = useState(location.mode ?? "edit");

  useEffect(() => { getRole(); getOrganizations(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function getRole() {
    RoleBackend.getRole(orgFromProps, roleNameFromUrl).then((res: any) => {
      if (res.data === null) { history.push("/404"); return; }
      if (res.status === "error") { Setting.showMessage("error", res.msg); return; }
      setRole(res.data);
    });
  }

  function getOrganizations() {
    OrganizationBackend.getOrganizations("admin").then((res: any) => { setOrganizations(res.data || []); });
  }

  function updateField(key: string, value: any) {
    setRole({...role, [key]: value});
  }

  function submitEdit(exitAfterSave: boolean) {
    const roleCopy = Setting.deepCopy(role);
    RoleBackend.updateRole(orgFromProps, roleName, roleCopy).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully saved"));
        setRoleName(role.name);
        if (exitAfterSave) history.push("/roles");
        else history.push(`/roles/${role.owner}/${encodeURIComponent(role.name)}`);
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
        updateField("name", roleName);
      }
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleDelete() {
    RoleBackend.deleteRole(role).then((res: any) => {
      if (res.status === "ok") history.push("/roles");
      else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  if (!role) return null;

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("role:New Role") : i18next.t("role:Edit Role")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>

        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account)} value={role.owner} onChange={e => updateField("owner", e.target.value)}>
              {organizations.map((org: any) => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={role.name} onChange={e => updateField("name", e.target.value)} />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Display name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={role.displayName} onChange={e => updateField("displayName", e.target.value)} />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Description")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={role.description || ""} onChange={e => updateField("description", e.target.value)} />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("role:Sub users")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm h-20 font-mono" value={(role.users || []).join("\n")} onChange={e => updateField("users", e.target.value.split("\n").filter(Boolean))} placeholder="owner/username (one per line)" />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("role:Sub groups")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm h-20 font-mono" value={(role.groups || []).join("\n")} onChange={e => updateField("groups", e.target.value.split("\n").filter(Boolean))} placeholder="owner/group (one per line)" />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("role:Sub roles")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm h-20 font-mono" value={(role.roles || []).join("\n")} onChange={e => updateField("roles", e.target.value.split("\n").filter(Boolean))} placeholder="owner/role (one per line)" />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("role:Sub domains")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm h-20 font-mono" value={(role.domains || []).join("\n")} onChange={e => updateField("domains", e.target.value.split("\n").filter(Boolean))} placeholder="domain (one per line)" />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Is enabled")}</label>
            <button className={`w-12 h-6 rounded-full transition-colors ${role.isEnabled ? "bg-primary" : "bg-zinc-700"}`} onClick={() => updateField("isEnabled", !role.isEnabled)}>
              <div className={`w-5 h-5 rounded-full bg-white transition-transform ${role.isEnabled ? "translate-x-6" : "translate-x-0.5"}`} />
            </button>
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

export default RoleEditPage;

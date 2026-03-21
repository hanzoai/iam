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
import * as PermissionBackend from "./backend/PermissionBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as ModelBackend from "./backend/ModelBackend";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import {Button} from "./components/ui/button";
import moment from "moment";

interface PermissionEditPageProps {
  account: any;
  history: any;
  match: any;
  location: any;
  organizationName?: string;
}

function PermissionEditPage(props: PermissionEditPageProps) {
  const {account, history, match, location} = props;
  const orgFromProps = props.organizationName ?? match.params.organizationName;
  const permNameFromUrl = decodeURIComponent(match.params.permissionName);

  const [permissionName, setPermissionName] = useState(permNameFromUrl);
  const [permission, setPermission] = useState<any>(null);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [models, setModels] = useState<any[]>([]);
  const [resources, setResources] = useState<any[]>([]);
  const [model, setModel] = useState<any>(null);
  const [mode] = useState(location.mode ?? "edit");

  useEffect(() => {
    getPermission();
    getOrganizations();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function getPermission() {
    PermissionBackend.getPermission(orgFromProps, permNameFromUrl).then((res: any) => {
      if (res.data === null) { history.push("/404"); return; }
      if (res.status === "error") { Setting.showMessage("error", res.msg); return; }
      setPermission(res.data);
      getModels(res.data.owner);
      getResources(res.data.owner);
      if (res.data.model) getModel(res.data.model);
    });
  }

  function getOrganizations() { OrganizationBackend.getOrganizations("admin").then((res: any) => setOrganizations(res.data || [])); }
  function getModels(org: string) { ModelBackend.getModels(org).then((res: any) => { if (res.status === "ok") setModels(res.data || []); }); }
  function getResources(org: string) { ApplicationBackend.getApplicationsByOrganization("admin", org).then((res: any) => setResources(res.data || [])); }

  function getModel(modelId: string) {
    if (!modelId) return;
    const [org, name] = modelId.split("/");
    ModelBackend.getModel(org, name).then((res: any) => setModel(res.data));
  }

  function updateField(key: string, value: any) {
    if (key === "model") getModel(value);
    const updated = {...permission, [key]: value};
    setPermission(updated);
  }

  function hasRoleDefinition() {
    return model?.modelText?.includes("role_definition") ?? false;
  }

  function submitEdit(exitAfterSave: boolean) {
    if ((permission.users?.length === 0) && (permission.roles?.length === 0)) {
      Setting.showMessage("error", i18next.t("general:The users and roles cannot be empty at the same time")); return;
    }
    if (permission.resources?.length === 0) { Setting.showMessage("error", i18next.t("general:The resources cannot be empty")); return; }
    if (permission.actions?.length === 0) { Setting.showMessage("error", i18next.t("general:The actions cannot be empty")); return; }
    if (!Setting.isLocalAdminUser(account) && permission.submitter !== account.name) {
      Setting.showMessage("error", i18next.t("general:A normal user can only modify the permission submitted by itself")); return;
    }

    const copy = Setting.deepCopy(permission);
    PermissionBackend.updatePermission(orgFromProps, permissionName, copy).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully saved"));
        setPermissionName(permission.name);
        if (exitAfterSave) history.push("/permissions");
        else history.push(`/permissions/${permission.owner}/${encodeURIComponent(permission.name)}`);
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
        updateField("name", permissionName);
      }
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleDelete() {
    PermissionBackend.deletePermission(permission).then((res: any) => {
      if (res.status === "ok") history.push("/permissions");
      else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  if (!permission) return null;

  const actionOptions = permission.resourceType === "API"
    ? [{value: "POST", name: "POST"}, {value: "GET", name: "GET"}]
    : [{value: "Read", name: i18next.t("permission:Read")}, {value: "Write", name: i18next.t("permission:Write")}, {value: "Admin", name: i18next.t("general:Admin")}];

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("permission:New Permission") : i18next.t("permission:Edit Permission")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>

        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account)} value={permission.owner} onChange={e => { updateField("owner", e.target.value); getModels(e.target.value); getResources(e.target.value); }}>
              {organizations.map((org: any) => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>

          {[
            {label: i18next.t("general:Name"), key: "name"},
            {label: i18next.t("general:Display name"), key: "displayName"},
            {label: i18next.t("general:Description"), key: "description"},
          ].map(({label, key}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={permission[key] || ""} onChange={e => updateField(key, e.target.value)} />
            </div>
          ))}

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Model")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={permission.model || ""} onChange={e => updateField("model", e.target.value)}>
              <option value="">-</option>
              {models.map((m: any) => <option key={`${m.owner}/${m.name}`} value={`${m.owner}/${m.name}`}>{m.owner}/{m.name}</option>)}
            </select>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("role:Sub users")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm h-20 font-mono" value={(permission.users || []).join("\n")} onChange={e => updateField("users", e.target.value.split("\n").filter(Boolean))} placeholder="owner/username or * for all" />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("role:Sub roles")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm h-20 font-mono disabled:opacity-60" disabled={!hasRoleDefinition()} value={(permission.roles || []).join("\n")} onChange={e => updateField("roles", e.target.value.split("\n").filter(Boolean))} placeholder="owner/role or * for all" />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("role:Sub domains")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm h-16 font-mono" value={(permission.domains || []).join("\n")} onChange={e => updateField("domains", e.target.value.split("\n").filter(Boolean))} placeholder="domain or * for all" />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("permission:Resource type")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={permission.resourceType} onChange={e => { updateField("resourceType", e.target.value); updateField("resources", []); }}>
              <option value="Application">{i18next.t("general:Application")}</option>
              <option value="TreeNode">{i18next.t("permission:TreeNode")}</option>
              <option value="Custom">{i18next.t("general:Custom")}</option>
              <option value="API">API</option>
            </select>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("general:Resources")}</label>
            <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm h-16 font-mono" value={(permission.resources || []).join("\n")} onChange={e => updateField("resources", e.target.value.split("\n").filter(Boolean))} placeholder="resource name or * for all" />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("permission:Actions")}</label>
            <div className="flex flex-wrap gap-2">
              {actionOptions.map(opt => (
                <label key={opt.value} className="flex items-center gap-1.5 text-sm text-zinc-300">
                  <input type="checkbox" className="rounded border-zinc-600" checked={(permission.actions || []).includes(opt.value)} onChange={e => {
                    const actions = [...(permission.actions || [])];
                    if (e.target.checked) actions.push(opt.value);
                    else actions.splice(actions.indexOf(opt.value), 1);
                    updateField("actions", actions);
                  }} />
                  {opt.name}
                </label>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("permission:Effect")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={permission.effect} onChange={e => updateField("effect", e.target.value)}>
              <option value="Allow">{i18next.t("permission:Allow")}</option>
              <option value="Deny">{i18next.t("permission:Deny")}</option>
            </select>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Is enabled")}</label>
            <button className={`w-12 h-6 rounded-full transition-colors ${permission.isEnabled ? "bg-primary" : "bg-zinc-700"}`} onClick={() => updateField("isEnabled", !permission.isEnabled)}>
              <div className={`w-5 h-5 rounded-full bg-white transition-transform ${permission.isEnabled ? "translate-x-6" : "translate-x-0.5"}`} />
            </button>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("permission:Submitter")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm opacity-60" disabled value={permission.submitter || ""} readOnly />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("permission:Approver")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm opacity-60" disabled value={permission.approver || ""} readOnly />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("permission:Approve time")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm opacity-60" disabled value={Setting.getFormattedDate(permission.approveTime)} readOnly />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:State")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={!Setting.isLocalAdminUser(account)} value={permission.state} onChange={e => {
              const val = e.target.value;
              if (permission.state !== val) {
                if (val === "Approved") { updateField("approver", account.name); updateField("approveTime", moment().format()); }
                else { updateField("approver", ""); updateField("approveTime", ""); }
              }
              updateField("state", val);
            }}>
              <option value="Approved">{i18next.t("permission:Approved")}</option>
              <option value="Pending">{i18next.t("permission:Pending")}</option>
            </select>
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

export default PermissionEditPage;

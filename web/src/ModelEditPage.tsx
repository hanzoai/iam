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
import * as ModelBackend from "./backend/ModelBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import ModelEditor from "./CasbinEditor";
import {Button} from "./components/ui/button";

interface ModelEditPageProps {
  account: any;
  history: any;
  match: any;
  location: any;
  organizationName?: string;
}

function ModelEditPage(props: ModelEditPageProps) {
  const {account, history, match, location} = props;
  const orgFromProps = props.organizationName ?? match.params.organizationName;
  const modelNameFromUrl = match.params.modelName;

  const [modelName, setModelName] = useState(modelNameFromUrl);
  const [model, setModel] = useState<any>(null);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [mode] = useState(location.mode ?? "edit");

  useEffect(() => { getModel(); getOrganizations(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function getModel() {
    ModelBackend.getModel(orgFromProps, modelNameFromUrl).then((res: any) => {
      if (res.data === null) { history.push("/404"); return; }
      if (res.status === "error") { Setting.showMessage("error", res.msg); return; }
      setModel(res.data);
    });
  }

  function getOrganizations() { OrganizationBackend.getOrganizations("admin").then((res: any) => setOrganizations(res.data || [])); }

  function updateField(key: string, value: any) { setModel({...model, [key]: value}); }

  function submitEdit(exitAfterSave: boolean) {
    const copy = Setting.deepCopy(model);
    ModelBackend.updateModel(orgFromProps, modelName, copy).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully saved"));
        setModelName(model.name);
        if (exitAfterSave) history.push("/models");
        else history.push(`/models/${model.owner}/${model.name}`);
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
        updateField("name", modelName);
      }
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleDelete() {
    ModelBackend.deleteModel(model).then((res: any) => {
      if (res.status === "ok") history.push("/models");
      else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  if (!model) return null;

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("model:New Model") : i18next.t("model:Edit Model")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>

        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account) || Setting.builtInObject(model)} value={model.owner} onChange={e => updateField("owner", e.target.value)}>
              {organizations.map((org: any) => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={Setting.builtInObject(model)} value={model.name} onChange={e => updateField("name", e.target.value)} />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Display name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={model.displayName} onChange={e => updateField("displayName", e.target.value)} />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Description")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={model.description || ""} onChange={e => updateField("description", e.target.value)} />
          </div>

          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("model:Model text")}</label>
            <div className="relative h-[500px]">
              <ModelEditor model={model} onModelTextChange={(value: string) => updateField("modelText", value)} />
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

export default ModelEditPage;

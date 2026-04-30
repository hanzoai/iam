// @ts-nocheck
import React, {useEffect, useState} from "react";
import * as WebhookBackend from "./backend/WebhookBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import WebhookHeaderTable from "./table/WebhookHeaderTable";
import Editor from "./common/Editor";
import {Button} from "./components/ui/button";

const previewTemplate = {"id": 9078, "owner": "built-in", "name": "68f55b28-7380-46b1-9bde-64fe1576e3b3", "createdTime": "2022-01-01T01:03:42+08:00", "organization": "built-in", "clientIp": "159.89.126.192", "user": "admin", "method": "POST", "requestUri": "/v1/iam/add-application", "action": "login", "isTriggered": false, "object": "{}"};
const userTemplate = {"owner": "built-in", "name": "admin", "createdTime": "2020-07-16T21:46:52+08:00", "id": "9eb20f79", "type": "normal-user", "displayName": "Admin", "email": "admin@example.com"};

function WebhookEditPage(props) {
  const {account, history, match, location} = props;
  const webhookNameFromUrl = match.params.webhookName;
  const [webhookName, setWebhookName] = useState(webhookNameFromUrl);
  const [webhook, setWebhook] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [mode] = useState(location.mode ?? "edit");

  useEffect(() => {
    WebhookBackend.getWebhook("admin", webhookNameFromUrl).then((res) => { if (res.data === null) { history.push("/404"); return; } setWebhook(res.data); });
    OrganizationBackend.getOrganizations("admin").then((res) => setOrganizations(res.data || []));
  }, []);

  function updateField(key, value) {
    if (key === "objectFields") value = value.includes("All") ? ["All"] : value;
    setWebhook({...webhook, [key]: value});
  }

  function submitEdit(exitAfterSave) {
    WebhookBackend.updateWebhook(webhook.owner, webhookName, Setting.deepCopy(webhook)).then((res) => {
      if (res.status === "ok") { Setting.showMessage("success", i18next.t("general:Successfully saved")); setWebhookName(webhook.name); if (exitAfterSave) history.push("/webhooks"); else history.push(`/webhooks/${webhook.name}`); }
      else { Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`); updateField("name", webhookName); }
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleDelete() {
    WebhookBackend.deleteWebhook(webhook).then((res) => { if (res.status === "ok") history.push("/webhooks"); else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`); })
      .catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  if (!webhook) return null;

  const preview = Setting.deepCopy(previewTemplate);
  if (webhook.isUserExtended) { preview["extendedUser"] = webhook.tokenFields?.length ? Object.fromEntries(webhook.tokenFields.map(f => [f.replace(f[0], f[0].toLowerCase()), userTemplate[f.replace(f[0], f[0].toLowerCase())]])) : userTemplate; }
  const previewText = JSON.stringify(preview, null, 2);

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("webhook:New Webhook") : i18next.t("webhook:Edit Webhook")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account)} value={webhook.organization} onChange={e => updateField("organization", e.target.value)}>
              {organizations.map(org => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={webhook.name} onChange={e => updateField("name", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:URL")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={webhook.url} onChange={e => updateField("url", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Method")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={webhook.method} onChange={e => updateField("method", e.target.value)}>
              {["POST", "GET", "PUT", "DELETE"].map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("webhook:Content type")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={webhook.contentType} onChange={e => updateField("contentType", e.target.value)}>
              <option value="application/json">application/json</option>
              <option value="application/x-www-form-urlencoded">application/x-www-form-urlencoded</option>
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("webhook:Headers")}</label>
            <WebhookHeaderTable title={i18next.t("webhook:Headers")} table={webhook.headers} onUpdateTable={(value) => updateField("headers", value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("webhook:Events")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" multiple value={webhook.events} onChange={e => updateField("events", Array.from(e.target.selectedOptions, o => o.value))}>
              {Setting.getApiPaths().map(opt => <option key={opt} value={opt}>{opt}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("webhook:Is user extended")}</label>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" checked={webhook.isUserExtended} onChange={e => updateField("isUserExtended", e.target.checked)} />
              <div className="w-9 h-5 bg-zinc-700 peer-checked:bg-blue-600 rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full"></div>
            </label>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("webhook:Single org only")}</label>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" checked={webhook.singleOrgOnly} onChange={e => updateField("singleOrgOnly", e.target.checked)} />
              <div className="w-9 h-5 bg-zinc-700 peer-checked:bg-blue-600 rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full"></div>
            </label>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Is enabled")}</label>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" checked={webhook.isEnabled} onChange={e => updateField("isEnabled", e.target.checked)} />
              <div className="w-9 h-5 bg-zinc-700 peer-checked:bg-blue-600 rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full"></div>
            </label>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("general:Preview")}</label>
            <div className="h-[300px]"><Editor value={previewText} lang="js" fillHeight readOnly dark /></div>
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

export default WebhookEditPage;

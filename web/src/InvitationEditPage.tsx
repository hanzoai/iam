// @ts-nocheck
import React, {useEffect, useState} from "react";
import * as InvitationBackend from "./backend/InvitationBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import * as GroupBackend from "./backend/GroupBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import copy from "copy-to-clipboard";
import {Button} from "./components/ui/button";
import {Copy, Send} from "lucide-react";

function InvitationEditPage(props) {
  const {account, history, match, location} = props;
  const orgNameFromUrl = props.organizationName ?? match.params.organizationName;
  const invNameFromUrl = match.params.invitationName;
  const [invitationName, setInvitationName] = useState(invNameFromUrl);
  const [invitation, setInvitation] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [applications, setApplications] = useState([]);
  const [groups, setGroups] = useState([]);
  const [mode] = useState(location.mode ?? "edit");
  const [emails, setEmails] = useState("");
  const [showSendModal, setShowSendModal] = useState(false);
  const [sendLoading, setSendLoading] = useState(false);

  useEffect(() => {
    InvitationBackend.getInvitation(orgNameFromUrl, invNameFromUrl).then((res) => { if (res.data === null) { history.push("/404"); return; } setInvitation(res.data); });
    OrganizationBackend.getOrganizations("admin").then((res) => setOrganizations(res.data || []));
    ApplicationBackend.getApplicationsByOrganization("admin", orgNameFromUrl).then((res) => setApplications(res.data || []));
    GroupBackend.getGroups(orgNameFromUrl).then((res) => { if (res.status === "ok") setGroups(res.data || []); });
  }, []);

  function updateField(key, value) { setInvitation({...invitation, [key]: value}); }

  function copySignupLink() {
    let defaultApplication;
    if (invitation.owner === "built-in") { defaultApplication = "app-hanzo"; }
    else {
      const selectedOrg = Setting.getArrayItem(organizations, "name", invitation.owner);
      defaultApplication = selectedOrg?.defaultApplication;
      if (!defaultApplication) { Setting.showMessage("error", i18next.t("invitation:You need to first specify a default application for organization: ") + selectedOrg?.name); return; }
    }
    copy(`${window.location.origin}/signup/${defaultApplication}?invitationCode=${invitation?.defaultCode}`);
    Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully"));
  }

  function submitEdit(exitAfterSave) {
    InvitationBackend.updateInvitation(orgNameFromUrl, invitationName, Setting.deepCopy(invitation)).then((res) => {
      if (res.status === "ok") { Setting.showMessage("success", i18next.t("general:Successfully saved")); setInvitationName(invitation.name); if (exitAfterSave) history.push("/invitations"); else history.push(`/invitations/${invitation.owner}/${invitation.name}`); }
      else { Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`); updateField("name", invitationName); }
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleDelete() {
    InvitationBackend.deleteInvitation(invitation).then((res) => { if (res.status === "ok") history.push("/invitations"); else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`); })
      .catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  if (!invitation) return null;
  const isCreatedByPlan = invitation.tag === "auto_created_invitation_for_plan";

  return (
    <div className="space-y-6">
      {showSendModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowSendModal(false)}>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 w-[500px] max-h-[80vh] overflow-auto" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-white mb-4">{i18next.t("general:Send")}</h3>
            <p className="text-zinc-400 mb-3">You will send invitation email to:</p>
            <div className="space-y-1 mb-4">{emails.split("\n").filter(e => Setting.isValidEmail(e)).map(e => <div key={e} className="text-zinc-300 text-sm bg-zinc-800 px-3 py-1 rounded">{e}</div>)}</div>
            <Button loading={sendLoading} onClick={() => {
              setSendLoading(true);
              const validEmails = emails.split("\n").filter(e => Setting.isValidEmail(e));
              InvitationBackend.sendInvitation(invitation, validEmails).then(res => { setSendLoading(false); if (res.status === "error") Setting.showMessage("error", res.msg); else Setting.showMessage("success", i18next.t("general:Successfully sent")); }).catch(err => { setSendLoading(false); Setting.showMessage("error", err.message); });
            }}>{i18next.t("general:Send")}</Button>
          </div>
        </div>
      )}
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("invitation:New Invitation") : i18next.t("invitation:Edit Invitation")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>
        <div className="p-6 space-y-5">
          {[
            {label: i18next.t("general:Organization"), key: "owner", type: "select", options: organizations.map(o => ({id: o.name, name: o.name})), disabled: !Setting.isAdminUser(account) || isCreatedByPlan},
            {label: i18next.t("general:Name"), key: "name", disabled: isCreatedByPlan},
            {label: i18next.t("general:Display name"), key: "displayName"},
            {label: i18next.t("invitation:Code"), key: "code"},
            {label: i18next.t("invitation:Default code"), key: "defaultCode"},
          ].map(({label, key, type, options, disabled}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              {type === "select" ? (
                <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={disabled} value={invitation[key] ?? ""} onChange={e => { updateField(key, e.target.value); if (key === "owner") { ApplicationBackend.getApplicationsByOrganization("admin", e.target.value).then(r => setApplications(r.data || [])); GroupBackend.getGroups(e.target.value).then(r => { if (r.status === "ok") setGroups(r.data || []); }); } }}>
                  {options?.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
                </select>
              ) : (
                <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm disabled:opacity-60" disabled={disabled} value={invitation[key] ?? ""} onChange={e => updateField(key, e.target.value)} />
              )}
            </div>
          ))}
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400"></label>
            <Button variant="outline" size="sm" onClick={copySignupLink}><Copy className="w-3 h-3 mr-1" />{i18next.t("application:Copy signup page URL")}</Button>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("general:Send")}</label>
            <div className="space-y-2">
              <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm min-h-[80px]" value={emails} onChange={e => setEmails(e.target.value)} />
              <Button size="sm" onClick={() => setShowSendModal(true)}><Send className="w-3 h-3 mr-1" />{i18next.t("general:Send")}</Button>
            </div>
          </div>
          {[
            {label: i18next.t("invitation:Quota"), key: "quota", type: "number"},
            {label: i18next.t("invitation:Used count"), key: "usedCount", type: "number"},
          ].map(({label, key, type}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={invitation[key] ?? 0} onChange={e => updateField(key, parseInt(e.target.value) || 0)} />
            </div>
          ))}
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Application")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={invitation.application} onChange={e => updateField("application", e.target.value)}>
              <option value="All">{i18next.t("general:All")}</option>
              {applications.map(a => <option key={a.name} value={a.name}>{a.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:State")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={invitation.state} onChange={e => updateField("state", e.target.value)}>
              <option value="Active">{i18next.t("subscription:Active")}</option>
              <option value="Suspended">{i18next.t("subscription:Suspended")}</option>
            </select>
          </div>
          {[
            {label: i18next.t("signup:Username"), key: "username"},
            {label: i18next.t("general:Email"), key: "email"},
            {label: i18next.t("general:Phone"), key: "phone"},
          ].map(({label, key}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={invitation[key] ?? ""} onChange={e => updateField(key, e.target.value)} />
            </div>
          ))}
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

export default InvitationEditPage;

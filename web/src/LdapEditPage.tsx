// @ts-nocheck
import React, {useEffect, useState} from "react";
import * as LdapBackend from "./backend/LdapBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as GroupBackend from "./backend/GroupBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import AttributesMapperTable from "./table/AttributesMapperTable";
import {Button} from "./components/ui/button";
import {Eye, EyeOff} from "lucide-react";

function LdapEditPage(props) {
  const {account, history, match} = props;
  const ldapIdFromUrl = match.params.ldapId;
  const orgNameFromUrl = match.params.organizationName;
  const [organizationName, setOrganizationName] = useState(orgNameFromUrl);
  const [ldap, setLdap] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [groups, setGroups] = useState([]);
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    LdapBackend.getLdap(orgNameFromUrl, ldapIdFromUrl).then(r => { if (r.status === "ok") setLdap(r.data); else Setting.showMessage("error", r.msg); });
    OrganizationBackend.getOrganizations("admin").then(r => setOrganizations(r.data || []));
    GroupBackend.getGroups(orgNameFromUrl).then(r => { if (r.status === "ok") setGroups(r.data || []); });
  }, []);

  function updateField(key, value) { setLdap({...ldap, [key]: value}); }

  function submitEdit(exitAfterSave) {
    LdapBackend.updateLdap(ldap).then(r => {
      if (r.status === "ok") { Setting.showMessage("success", "Update LDAP server success"); setOrganizationName(ldap.owner); if (exitAfterSave) history.push(`/organizations/${ldap.owner}`); }
      else Setting.showMessage("error", r.msg);
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to update")}: ${error}`));
  }

  if (!ldap) return null;

  const filterFieldOptions = [{value: "uid", label: "uid"}, {value: "mail", label: "Email"}, {value: "mobile", label: "mobile"}, {value: "sAMAccountName", label: "sAMAccountName"}];

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{i18next.t("ldap:Edit LDAP")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            <Button variant="outline" onClick={() => Setting.goToLink(`/ldap/sync/${organizationName}/${ldapIdFromUrl}`)}>{i18next.t("general:Sync")} LDAP</Button>
          </div>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account)} value={ldap.owner} onChange={e => updateField("owner", e.target.value)}>
              {organizations.map(org => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:ID")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm opacity-60" disabled value={ldap.id} />
          </div>
          {[{label: i18next.t("ldap:Server name"), key: "serverName"}, {label: i18next.t("ldap:Server host"), key: "host"}, {label: i18next.t("ldap:Base DN"), key: "baseDn"}, {label: i18next.t("ldap:Search Filter"), key: "filter"}, {label: i18next.t("general:Admin"), key: "username"}].map(({label, key}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={ldap[key] || ""} onChange={e => updateField(key, e.target.value)} />
            </div>
          ))}
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("ldap:Server port")}</label>
            <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" min={0} max={65535} value={ldap.port} onChange={e => updateField("port", parseInt(e.target.value) || 0)} />
          </div>
          {[{label: i18next.t("ldap:Enable SSL"), key: "enableSsl"}, {label: i18next.t("ldap:Allow self-signed certificate"), key: "allowSelfSignedCert"}].map(({label, key}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" checked={ldap[key]} onChange={e => updateField(key, e.target.checked)} />
                <div className="w-9 h-5 bg-zinc-700 peer-checked:bg-blue-600 rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full"></div>
              </label>
            </div>
          ))}
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("ldap:Admin Password")}</label>
            <div className="relative">
              <input type={showPassword ? "text" : "password"} className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm pr-10" value={ldap.password || ""} onChange={e => updateField("password", e.target.value)} />
              <button className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-white" onClick={() => setShowPassword(!showPassword)}>
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Password type")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={ldap.passwordType || ""} onChange={e => updateField("passwordType", e.target.value)}>
              <option value="Plain">{i18next.t("general:Plain")}</option>
              <option value="SSHA">SSHA</option>
              <option value="MD5">MD5</option>
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("ldap:Default group")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={ldap.defaultGroup || ""} onChange={e => updateField("defaultGroup", e.target.value)}>
              <option value="">{i18next.t("general:Default")}</option>
              {groups?.map(g => <option key={g.name} value={`${g.owner}/${g.name}`}>{g.displayName}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("ldap:Custom attributes")}</label>
            <AttributesMapperTable customAttributes={ldap.customAttributes} onUpdateTable={v => updateField("customAttributes", v)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("ldap:Auto Sync")}</label>
            <div className="flex items-center gap-2">
              <input type="number" className="w-24 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" min={0} value={ldap.autoSync} onChange={e => updateField("autoSync", parseInt(e.target.value) || 0)} />
              <span className="text-zinc-400 text-sm">mins</span>
              {ldap.autoSync > 0 && <span className="text-yellow-400 text-sm ml-4">{i18next.t("ldap:The Auto Sync option will sync all users to specify organization")}</span>}
            </div>
          </div>
        </div>
      </div>
      <div className="flex gap-3 px-6">
        <Button variant="outline" size="lg" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
        <Button size="lg" onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
      </div>
    </div>
  );
}

export default LdapEditPage;

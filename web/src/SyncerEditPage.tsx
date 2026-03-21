// @ts-nocheck
import React, {useEffect, useState} from "react";
import * as SyncerBackend from "./backend/SyncerBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as CertBackend from "./backend/CertBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import SyncerTableColumnTable from "./table/SyncerTableColumnTable";
import Editor from "./common/Editor";
import {Button} from "./components/ui/button";
import {Eye, EyeOff, Link as LinkIcon} from "lucide-react";

function getSyncerTableColumns(syncer) {
  const keycloakCols = [{name:"ID",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"USERNAME",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"LAST_NAME+FIRST_NAME",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"EMAIL",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"EMAIL_VERIFIED",type:"boolean",iamName:"EmailVerified",isHashed:true,values:[]},{name:"FIRST_NAME",type:"string",iamName:"FirstName",isHashed:true,values:[]},{name:"LAST_NAME",type:"string",iamName:"LastName",isHashed:true,values:[]},{name:"CREATED_TIMESTAMP",type:"string",iamName:"CreatedTime",isHashed:true,values:[]},{name:"ENABLED",type:"boolean",iamName:"IsForbidden",isHashed:true,values:[]}];
  const wecomCols = [{name:"userid",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"name",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"email",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"mobile",type:"string",iamName:"Phone",isHashed:true,values:[]},{name:"avatar",type:"string",iamName:"Avatar",isHashed:true,values:[]},{name:"position",type:"string",iamName:"Title",isHashed:true,values:[]},{name:"gender",type:"string",iamName:"Gender",isHashed:true,values:[]}];
  const azureCols = [{name:"id",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"userPrincipalName",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"displayName",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"givenName",type:"string",iamName:"FirstName",isHashed:true,values:[]},{name:"surname",type:"string",iamName:"LastName",isHashed:true,values:[]},{name:"mail",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"mobilePhone",type:"string",iamName:"Phone",isHashed:true,values:[]},{name:"jobTitle",type:"string",iamName:"Title",isHashed:true,values:[]},{name:"officeLocation",type:"string",iamName:"Location",isHashed:true,values:[]},{name:"preferredLanguage",type:"string",iamName:"Language",isHashed:true,values:[]},{name:"accountEnabled",type:"boolean",iamName:"IsForbidden",isHashed:true,values:[]}];
  const googleCols = [{name:"id",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"primaryEmail",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"name.fullName",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"name.givenName",type:"string",iamName:"FirstName",isHashed:true,values:[]},{name:"name.familyName",type:"string",iamName:"LastName",isHashed:true,values:[]},{name:"suspended",type:"boolean",iamName:"IsForbidden",isHashed:true,values:[]},{name:"isAdmin",type:"boolean",iamName:"IsAdmin",isHashed:true,values:[]}];
  const dingtalkCols = [{name:"userid",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"unionid",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"name",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"email",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"mobile",type:"string",iamName:"Phone",isHashed:true,values:[]},{name:"avatar",type:"string",iamName:"Avatar",isHashed:true,values:[]},{name:"title",type:"string",iamName:"Title",isHashed:true,values:[]},{name:"job_number",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"active",type:"boolean",iamName:"IsForbidden",isHashed:true,values:[]}];
  const adCols = [{name:"objectGUID",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"sAMAccountName",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"displayName",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"givenName",type:"string",iamName:"FirstName",isHashed:true,values:[]},{name:"sn",type:"string",iamName:"LastName",isHashed:true,values:[]},{name:"mail",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"mobile",type:"string",iamName:"Phone",isHashed:true,values:[]},{name:"title",type:"string",iamName:"Title",isHashed:true,values:[]},{name:"department",type:"string",iamName:"Affiliation",isHashed:true,values:[]},{name:"userAccountControl",type:"string",iamName:"IsForbidden",isHashed:true,values:[]}];
  const larkCols = [{name:"user_id",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"name",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"email",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"mobile",type:"string",iamName:"Phone",isHashed:true,values:[]},{name:"avatar",type:"string",iamName:"Avatar",isHashed:true,values:[]},{name:"job_title",type:"string",iamName:"Title",isHashed:true,values:[]},{name:"gender",type:"number",iamName:"Gender",isHashed:true,values:[]}];
  const oktaCols = [{name:"id",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"profile.login",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"profile.displayName",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"profile.firstName",type:"string",iamName:"FirstName",isHashed:true,values:[]},{name:"profile.lastName",type:"string",iamName:"LastName",isHashed:true,values:[]},{name:"profile.email",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"profile.mobilePhone",type:"string",iamName:"Phone",isHashed:true,values:[]},{name:"profile.title",type:"string",iamName:"Title",isHashed:true,values:[]},{name:"profile.preferredLanguage",type:"string",iamName:"Language",isHashed:true,values:[]},{name:"status",type:"string",iamName:"IsForbidden",isHashed:true,values:[]}];
  const scimCols = [{name:"id",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"userName",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"displayName",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"name.givenName",type:"string",iamName:"FirstName",isHashed:true,values:[]},{name:"name.familyName",type:"string",iamName:"LastName",isHashed:true,values:[]},{name:"emails",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"phoneNumbers",type:"string",iamName:"Phone",isHashed:true,values:[]},{name:"title",type:"string",iamName:"Title",isHashed:true,values:[]},{name:"preferredLanguage",type:"string",iamName:"Language",isHashed:true,values:[]},{name:"active",type:"boolean",iamName:"IsForbidden",isHashed:true,values:[]}];
  const awsCols = [{name:"UserId",type:"string",iamName:"Id",isHashed:true,values:[]},{name:"UserName",type:"string",iamName:"Name",isHashed:true,values:[]},{name:"UserName",type:"string",iamName:"DisplayName",isHashed:true,values:[]},{name:"Tags.Email",type:"string",iamName:"Email",isHashed:true,values:[]},{name:"Tags.Phone",type:"string",iamName:"Phone",isHashed:true,values:[]},{name:"Tags.FirstName",type:"string",iamName:"FirstName",isHashed:true,values:[]},{name:"Tags.LastName",type:"string",iamName:"LastName",isHashed:true,values:[]},{name:"Tags.Title",type:"string",iamName:"Title",isHashed:true,values:[]},{name:"Tags.Department",type:"string",iamName:"Affiliation",isHashed:true,values:[]},{name:"CreateDate",type:"string",iamName:"CreatedTime",isHashed:true,values:[]}];
  const map = {Keycloak: keycloakCols, WeCom: wecomCols, "Azure AD": azureCols, "Google Workspace": googleCols, DingTalk: dingtalkCols, "Active Directory": adCols, Lark: larkCols, Okta: oktaCols, SCIM: scimCols, "AWS IAM": awsCols};
  return map[syncer.type] || [];
}

function SyncerEditPage(props) {
  const {account, history, match, location} = props;
  const syncerNameFromUrl = match.params.syncerName;
  const [syncerName, setSyncerName] = useState(syncerNameFromUrl);
  const [syncer, setSyncer] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [certs, setCerts] = useState([]);
  const [mode] = useState(location.mode ?? "edit");
  const [testDbLoading, setTestDbLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    SyncerBackend.getSyncer("admin", syncerNameFromUrl).then(r => {
      if (r.data === null) { history.push("/404"); return; }
      if (r.status === "error") { Setting.showMessage("error", r.msg); return; }
      setSyncer(r.data);
      if (r.data?.organization) CertBackend.getCerts(r.data.organization).then(cr => setCerts(cr.data || []));
    });
    OrganizationBackend.getOrganizations("admin").then(r => setOrganizations(r.data || []));
  }, []);

  function updateField(key, value) {
    if (["port"].includes(key)) value = Setting.myParseInt(value);
    const s = {...syncer};
    if (key === "organization" && s.organization !== value) { s.cert = ""; CertBackend.getCerts(value).then(r => setCerts(r.data || [])); }
    s[key] = value;
    setSyncer(s);
  }

  function needSshFields() { return syncer.type === "Database" && ["mysql", "mssql", "postgres"].includes(syncer.databaseType); }
  const nonDbTypes = ["WeCom", "Azure AD", "Google Workspace", "DingTalk", "Lark", "Okta", "SCIM", "AWS IAM"];
  const isNonDb = nonDbTypes.includes(syncer?.type);

  function submitEdit(exitAfterSave) {
    SyncerBackend.updateSyncer(syncer.owner, syncerName, Setting.deepCopy(syncer)).then(r => {
      if (r.status === "ok") { Setting.showMessage("success", i18next.t("general:Successfully saved")); setSyncerName(syncer.name); if (exitAfterSave) history.push("/syncers"); else history.push(`/syncers/${syncer.name}`); }
      else { Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${r.msg}`); updateField("name", syncerName); }
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleDelete() {
    SyncerBackend.deleteSyncer(syncer).then(r => { if (r.status === "ok") history.push("/syncers"); else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${r.msg}`); })
      .catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  if (!syncer) return null;

  const hostLabel = syncer.type === "Azure AD" ? i18next.t("provider:Tenant ID") : syncer.type === "Google Workspace" ? i18next.t("syncer:Admin Email") : syncer.type === "Active Directory" ? i18next.t("ldap:Server") : syncer.type === "SCIM" ? i18next.t("syncer:SCIM Server URL") : syncer.type === "AWS IAM" ? i18next.t("syncer:AWS Region") : i18next.t("provider:Host");
  const userLabel = syncer.type === "WeCom" ? i18next.t("syncer:Corp ID") : syncer.type === "DingTalk" ? i18next.t("provider:App Key") : syncer.type === "Lark" ? i18next.t("provider:App ID") : syncer.type === "Azure AD" ? i18next.t("provider:Client ID") : syncer.type === "Active Directory" ? i18next.t("syncer:Bind DN") : syncer.type === "SCIM" ? i18next.t("syncer:Username (optional)") : syncer.type === "AWS IAM" ? i18next.t("syncer:AWS Access Key ID") : i18next.t("general:User");
  const passLabel = syncer.type === "WeCom" ? i18next.t("syncer:Corp secret") : syncer.type === "DingTalk" || syncer.type === "Lark" ? i18next.t("provider:App secret") : syncer.type === "Azure AD" ? i18next.t("provider:Client secret") : syncer.type === "Google Workspace" ? i18next.t("syncer:Service account key") : syncer.type === "SCIM" ? i18next.t("syncer:API Token / Password") : syncer.type === "AWS IAM" ? i18next.t("syncer:AWS Secret Access Key") : i18next.t("general:Password");

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{mode === "add" ? i18next.t("syncer:New Syncer") : i18next.t("syncer:Edit Syncer")}</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => submitEdit(false)}>{i18next.t("general:Save")}</Button>
            <Button onClick={() => submitEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
            {mode === "add" && <Button variant="outline" onClick={handleDelete}>{i18next.t("general:Cancel")}</Button>}
          </div>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account)} value={syncer.organization} onChange={e => updateField("organization", e.target.value)}>
              {organizations.map(org => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Name")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.name} onChange={e => updateField("name", e.target.value)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Type")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.type} onChange={e => {
              const val = e.target.value; updateField("type", val);
              const s = {...syncer, type: val}; s.tableColumns = getSyncerTableColumns(s);
              if (val === "Keycloak") s.table = "user_entity";
              setSyncer(s);
            }}>
              {["Database", "Keycloak", "WeCom", "Azure AD", "Active Directory", "Google Workspace", "DingTalk", "Lark", "Okta", "SCIM", "AWS IAM"].map(item => <option key={item} value={item}>{item}</option>)}
            </select>
          </div>
          {!isNonDb && syncer.type !== "Active Directory" && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{i18next.t("syncer:Database type")}</label>
              <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.databaseType} onChange={e => { updateField("databaseType", e.target.value); updateField("sslMode", e.target.value === "postgres" ? "disable" : ""); }}>
                {[{id:"mysql",name:"MySQL"},{id:"postgres",name:"PostgreSQL"},{id:"mssql",name:"SQL Server"},{id:"oracle",name:"Oracle"},{id:"sqlite3",name:"Sqlite 3"}].map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select>
            </div>
          )}
          {syncer.databaseType === "postgres" && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{i18next.t("provider:SSL mode")}</label>
              <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.sslMode} onChange={e => updateField("sslMode", e.target.value)}>
                {["disable","require","verify-ca","verify-full"].map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
          )}
          {!["WeCom","DingTalk","Lark"].includes(syncer.type) && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{hostLabel}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.host || ""} onChange={e => updateField("host", e.target.value)} />
            </div>
          )}
          {!isNonDb && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{syncer.type === "Active Directory" ? i18next.t("provider:LDAP port") : i18next.t("provider:Port")}</label>
              <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.port} onChange={e => updateField("port", parseInt(e.target.value) || 0)} />
            </div>
          )}
          {syncer.type !== "Google Workspace" && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{userLabel}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.user || ""} onChange={e => updateField("user", e.target.value)} />
            </div>
          )}
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{passLabel}</label>
            {syncer.type === "Google Workspace" ? (
              <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm min-h-[100px]" value={syncer.password || ""} onChange={e => updateField("password", e.target.value)} placeholder={i18next.t("syncer:Paste your Google Workspace service account JSON key here")} />
            ) : (
              <div className="relative">
                <input type={showPassword ? "text" : "password"} className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm pr-10" value={syncer.password || ""} onChange={e => updateField("password", e.target.value)} />
                <button className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-white" onClick={() => setShowPassword(!showPassword)}>
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            )}
          </div>
          {!isNonDb && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{syncer.type === "Active Directory" ? i18next.t("ldap:Base DN") : i18next.t("syncer:Database")}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.database || ""} onChange={e => updateField("database", e.target.value)} />
            </div>
          )}
          {needSshFields() && (
            <>
              <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                <label className="text-sm text-zinc-400">{i18next.t("general:SSH type")}</label>
                <div className="flex gap-2">
                  {[{v:"",l:i18next.t("general:None")},{v:"password",l:i18next.t("general:Password")},{v:"cert",l:i18next.t("general:Cert")}].map(({v,l}) => (
                    <button key={v} className={`px-3 py-1.5 rounded text-sm border ${syncer.sshType === v ? "bg-white text-black border-white" : "border-zinc-700 text-zinc-400 hover:text-white"}`} onClick={() => updateField("sshType", v)}>{l}</button>
                  ))}
                </div>
              </div>
              {syncer.sshType && (
                <>
                  <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                    <label className="text-sm text-zinc-400">{i18next.t("syncer:SSH host")}</label>
                    <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.sshHost || ""} onChange={e => updateField("sshHost", e.target.value)} />
                  </div>
                  <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                    <label className="text-sm text-zinc-400">{i18next.t("syncer:SSH port")}</label>
                    <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.sshPort} onChange={e => updateField("sshPort", parseInt(e.target.value) || 0)} />
                  </div>
                  <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                    <label className="text-sm text-zinc-400">{i18next.t("syncer:SSH user")}</label>
                    <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.sshUser || ""} onChange={e => updateField("sshUser", e.target.value)} />
                  </div>
                  {syncer.sshType === "password" ? (
                    <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                      <label className="text-sm text-zinc-400">{i18next.t("syncer:SSH password")}</label>
                      <input type="password" className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.sshPassword || ""} onChange={e => updateField("sshPassword", e.target.value)} />
                    </div>
                  ) : (
                    <div className="grid grid-cols-[160px_1fr] items-center gap-4">
                      <label className="text-sm text-zinc-400">{i18next.t("general:SSH cert")}</label>
                      <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.cert || ""} onChange={e => updateField("cert", e.target.value)}>
                        {certs.map(c => <option key={c.name} value={c.name}>{c.name}</option>)}
                      </select>
                    </div>
                  )}
                </>
              )}
            </>
          )}
          {!isNonDb && (
            <div className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{i18next.t("syncer:Table")}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.table || ""} onChange={e => updateField("table", e.target.value)} />
            </div>
          )}
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("provider:Syncer test")}</label>
            <Button size="sm" disabled={testDbLoading} onClick={() => {
              setTestDbLoading(true);
              SyncerBackend.testSyncerDb(syncer).then(r => { setTestDbLoading(false); if (r.status === "ok") Setting.showMessage("success", i18next.t("syncer:Connect successfully")); else Setting.showMessage("error", `${i18next.t("syncer:Failed to connect")}: ${r.msg}`); })
                .catch(error => { setTestDbLoading(false); Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`); });
            }}>{testDbLoading ? "Testing..." : i18next.t("syncer:Test Connection")}</Button>
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("syncer:Table columns")}</label>
            <SyncerTableColumnTable title={i18next.t("syncer:Table columns")} table={syncer.tableColumns} onUpdateTable={v => updateField("tableColumns", v)} />
          </div>
          {[{label: i18next.t("syncer:Affiliation table"), key: "affiliationTable"}, {label: i18next.t("syncer:Avatar base URL"), key: "avatarBaseUrl"}].map(({label, key}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer[key] || ""} onChange={e => updateField(key, e.target.value)} />
            </div>
          ))}
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("syncer:Sync interval")}</label>
            <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={syncer.syncInterval} onChange={e => updateField("syncInterval", parseInt(e.target.value) || 0)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("syncer:Error text")}</label>
            <div className="h-[300px]"><Editor value={syncer.errorText} fillHeight readOnly dark lang="js" onChange={v => updateField("errorText", v)} /></div>
          </div>
          {[{label: i18next.t("syncer:Is read-only"), key: "isReadOnly"}, {label: i18next.t("general:Is enabled"), key: "isEnabled"}].map(({label, key}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" checked={syncer[key]} onChange={e => updateField(key, e.target.checked)} />
                <div className="w-9 h-5 bg-zinc-700 peer-checked:bg-blue-600 rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full"></div>
              </label>
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

export default SyncerEditPage;

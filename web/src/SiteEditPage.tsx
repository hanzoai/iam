// @ts-nocheck
import React, {useEffect, useState} from "react";
import * as ProviderBackend from "./backend/ProviderBackend";
import * as SiteBackend from "./backend/SiteBackend";
import * as CertBackend from "./backend/CertBackend";
import * as RuleBackend from "./backend/RuleBackend";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import RuleTable from "./table/RuleTable";
import {Button} from "./components/ui/button";

function SiteEditPage(props) {
  const {account, history, match} = props;
  const ownerFromUrl = match.params.organizationName;
  const siteNameFromUrl = match.params.siteName;
  const [owner, setOwner] = useState(ownerFromUrl);
  const [siteName, setSiteName] = useState(siteNameFromUrl);
  const [site, setSite] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [certs, setCerts] = useState([]);
  const [rules, setRules] = useState([]);
  const [applications, setApplications] = useState([]);
  const [providers, setProviders] = useState([]);

  useEffect(() => {
    if (Setting.isAdminUser(account)) OrganizationBackend.getOrganizations("admin").then(r => setOrganizations(r.data || []));
    SiteBackend.getSite(ownerFromUrl, siteNameFromUrl).then(r => { if (r.status === "ok") setSite(r.data); else Setting.showMessage("error", `Failed to get site: ${r.msg}`); });
    CertBackend.getCerts(ownerFromUrl).then(r => { if (r.status === "ok") setCerts(r.data || []); });
    RuleBackend.getRules(ownerFromUrl).then(r => { if (r.status === "ok") setRules(r.data || []); });
    ApplicationBackend.getApplicationsByOrganization("admin", ownerFromUrl).then(r => { if (r.status === "ok") setApplications(r.data || []); });
    ProviderBackend.getProviders().then(r => { if (r.status === "ok") setProviders(r.data?.filter(p => p.category === "SMS" || p.category === "Email").map(p => `${p.category}/${p.name}`) || []); });
  }, []);

  function updateField(key, value) { setSite({...site, [key]: value}); }

  function submitEdit() {
    SiteBackend.updateSite(owner, siteName, Setting.deepCopy(site)).then(r => {
      if (r.status === "error") { Setting.showMessage("error", `Failed to save: ${r.msg}`); updateField("name", siteName); }
      else { Setting.showMessage("success", "Successfully saved"); setOwner(site.owner); setSiteName(site.name); history.push(`/sites/${site.owner}/${site.name}`); }
    }).catch(error => Setting.showMessage("error", `failed to save: ${error}`));
  }

  if (!site) return null;

  return (
    <div className="space-y-6">
      <div className="border border-zinc-800 rounded-lg bg-zinc-900/30">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
          <h2 className="text-lg font-semibold text-white">{i18next.t("site:Edit Site")}</h2>
          <Button onClick={submitEdit}>{i18next.t("general:Save")}</Button>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("general:Organization")}</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={!Setting.isAdminUser(account)} value={site.owner} onChange={e => { updateField("owner", e.target.value); ApplicationBackend.getApplicationsByOrganization("admin", e.target.value).then(r => { if (r.status === "ok") setApplications(r.data || []); }); }}>
              {organizations.map(org => <option key={org.name} value={org.name}>{org.name}</option>)}
            </select>
          </div>
          {[{label: i18next.t("general:Name"), key: "name"}, {label: i18next.t("general:Display name"), key: "displayName"}, {label: i18next.t("general:Tag"), key: "tag"}, {label: i18next.t("site:Domain"), key: "domain"}, {label: i18next.t("site:Host"), key: "host"}].map(({label, key}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" value={site[key] || ""} onChange={e => updateField(key, e.target.value)} />
            </div>
          ))}
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("site:Port")}</label>
            <input type="number" className="w-40 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" min={0} max={65535} value={site.port} onChange={e => updateField("port", parseInt(e.target.value) || 0)} />
          </div>
          {[{label: i18next.t("site:Need redirect"), key: "needRedirect"}, {label: i18next.t("site:Disable verbose"), key: "disableVerbose"}, {label: i18next.t("site:Enable alert"), key: "enableAlert"}].map(({label, key}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" checked={site[key]} onChange={e => updateField(key, e.target.checked)} />
                <div className="w-9 h-5 bg-zinc-700 peer-checked:bg-blue-600 rounded-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full"></div>
              </label>
            </div>
          ))}
          <div className="grid grid-cols-[160px_1fr] items-start gap-4">
            <label className="text-sm text-zinc-400 pt-2">{i18next.t("site:Rules")}</label>
            <RuleTable title="Rules" account={account} sources={rules} rules={site.rules} onUpdateRules={v => updateField("rules", v)} />
          </div>
          <div className="grid grid-cols-[160px_1fr] items-center gap-4">
            <label className="text-sm text-zinc-400">{i18next.t("site:Public IP")}</label>
            <input className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm opacity-60" disabled value={site.publicIp || ""} readOnly />
          </div>
          {[{label: i18next.t("site:Mode"), key: "sslMode", options: [{id: "HTTP"}, {id: "HTTPS and HTTP"}, {id: "HTTPS Only"}, {id: "Static Folder"}]},
            {label: i18next.t("site:SSL cert"), key: "sslCert", options: certs?.map(c => ({id: c.name})), disabled: true},
            {label: i18next.t("site:IAM app"), key: "iamApplication", options: applications?.map(a => ({id: a.name}))},
            {label: i18next.t("site:Status"), key: "status", options: [{id: "Active"}, {id: "Inactive"}]},
          ].map(({label, key, options, disabled}) => (
            <div key={key} className="grid grid-cols-[160px_1fr] items-center gap-4">
              <label className="text-sm text-zinc-400">{label}</label>
              <select className="w-full bg-zinc-900 border border-zinc-700 rounded-md px-3 py-2 text-white text-sm" disabled={disabled} value={site[key] || ""} onChange={e => updateField(key, e.target.value)}>
                {options?.map(o => <option key={o.id} value={o.id}>{o.id}</option>)}
              </select>
            </div>
          ))}
        </div>
      </div>
      <div className="flex gap-3 px-6">
        <Button size="lg" onClick={submitEdit}>{i18next.t("general:Save")}</Button>
      </div>
    </div>
  );
}

export default SiteEditPage;

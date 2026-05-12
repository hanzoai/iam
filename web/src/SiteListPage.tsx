// @ts-nocheck
import React, {useEffect, useState, useCallback} from "react";
import {Link} from "react-router-dom";
import {Plus, Pencil, Trash2, ChevronLeft, ChevronRight} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as SiteBackend from "./backend/SiteBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";

function SiteListPage(props) {
  const {account, history} = props;
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 1000, total: 0});

  const fetchData = useCallback((params = {}) => {
    const field = params.searchedColumn || "";
    const value = params.searchText || "";
    const sf = params.sortField || "";
    const so = params.sortOrder || "";
    setLoading(true);
    (Setting.isDefaultOrganizationSelected(account) ? SiteBackend.getGlobalSites() : SiteBackend.getSites(Setting.getRequestOrganization(account), "", "", field, value, sf, so))
      .then((res) => {
        setLoading(false);
        if (res.status === "ok") { setData(res.data || []); setPagination(p => ({...p, total: res.data2})); }
        else Setting.showMessage("error", `Failed to get sites: ${res.msg}`);
      });
  }, [account]);

  useEffect(() => { fetchData(); }, []);

  function addSite() {
    const randomName = Setting.getRandomName();
    const owner = Setting.getRequestOrganization(account);
    const s = {owner, name: `site_${randomName}`, createdTime: moment().format(), displayName: `New Site - ${randomName}`, domain: "", otherDomains: [], needRedirect: false, disableVerbose: false, rules: [], enableAlert: false, alertInterval: 60, alertTryTimes: 3, alertProviders: [], challenges: [], host: "", port: 8000, hosts: [], sslMode: "HTTPS Only", sslCert: "", publicIp: "", node: "", isSelf: false, nodes: [], iamApplication: "", organizations: []};
    SiteBackend.addSite(s).then((res) => {
      if (res.status === "error") Setting.showMessage("error", `Failed to add: ${res.msg}`);
      else { Setting.showMessage("success", "Site added successfully"); fetchData(); }
    }).catch(error => Setting.showMessage("error", `Site failed to add: ${error}`));
  }

  function deleteSite(i) {
    SiteBackend.deleteSite(data[i]).then((res) => {
      if (res.status === "error") Setting.showMessage("error", `Failed to delete: ${res.msg}`);
      else { Setting.showMessage("success", "Site deleted successfully"); fetchData(); }
    }).catch(error => Setting.showMessage("error", `Site failed to delete: ${error}`));
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Sites")}</h2>
        <Button size="sm" onClick={addSite}><Plus className="w-4 h-4 mr-1" />{i18next.t("general:Add")}</Button>
      </div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800 bg-zinc-900/50">
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Owner")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Name")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Display name")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("site:Domain")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("site:Host")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("site:SSL cert")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Action")}</th>
            </tr></thead>
            <tbody>
              {loading ? (<tr><td colSpan={7} className="px-4 py-8 text-center text-zinc-500">Loading...</td></tr>) :
               (data || []).length === 0 ? (<tr><td colSpan={7} className="px-4 py-8 text-center text-zinc-500">No data</td></tr>) :
               (data || []).map((record, index) => (
                <tr key={record.name} className="border-b border-zinc-800/50 hover:bg-zinc-900/30">
                  <td className="px-4 py-3 text-zinc-300">{record.owner}</td>
                  <td className="px-4 py-3"><Link to={`/sites/${record.owner}/${record.name}`} className="text-blue-400 hover:text-blue-300">{record.name}</Link></td>
                  <td className="px-4 py-3 text-zinc-300">{record.displayName}</td>
                  <td className="px-4 py-3">{record.publicIp ? <a target="_blank" rel="noreferrer" href={`https://${record.domain}`} className="text-blue-400 hover:text-blue-300">{record.domain}</a> : <span className="text-zinc-300">{record.domain}</span>}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.host ? `${record.host}:${record.port}` : record.port}</td>
                  <td className="px-4 py-3"><Link to={`/certs/admin/${record.sslCert}`} className="text-blue-400 hover:text-blue-300">{record.sslCert}</Link></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Button variant="outline" size="sm" onClick={() => history.push(`/sites/${record.owner}/${record.name}`)}><Pencil className="w-3 h-3 mr-1" />{i18next.t("general:Edit")}</Button>
                      <Button variant="destructive" size="sm" onClick={() => { if (window.confirm(`Sure to delete site: ${record.name} ?`)) deleteSite(index); }}>
                        <Trash2 className="w-3 h-3 mr-1" />{i18next.t("general:Delete")}
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default SiteListPage;

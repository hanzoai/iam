// @ts-nocheck
import React, {useEffect, useState, useCallback, useRef} from "react";
import {Link} from "react-router-dom";
import {Upload, Trash2, ChevronLeft, ChevronRight, Copy} from "lucide-react";
import copy from "copy-to-clipboard";
import * as Setting from "./Setting";
import * as ResourceBackend from "./backend/ResourceBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";

function ResourceListPage(props) {
  const {account} = props;
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 10, total: 0});
  const [isAuthorized, setIsAuthorized] = useState(true);
  const fileInputRef = useRef(null);

  const fetchData = useCallback((params = {}) => {
    const field = params.searchedColumn || "";
    const value = params.searchText || "";
    const sf = params.sortField || "";
    const so = params.sortOrder || "";
    const pag = params.pagination || pagination;
    setLoading(true);
    ResourceBackend.getResources(Setting.isDefaultOrganizationSelected(account) ? "" : Setting.getRequestOrganization(account), account.name, pag.current, pag.pageSize, field, value, sf, so)
      .then((res) => {
        setLoading(false);
        if (res.status === "ok") { setData(res.data || []); setPagination({...pag, total: res.data2}); }
        else { if (res.data?.includes("Please login first")) setIsAuthorized(false); }
      });
  }, [account, pagination]);

  useEffect(() => { fetchData({pagination: {current: 1, pageSize: 10, total: 0}}); }, []);

  function deleteResource(i) {
    ResourceBackend.deleteResource(data[i]).then((res) => {
      if (res.status === "ok") { Setting.showMessage("success", i18next.t("general:Successfully deleted")); fetchData({pagination}); }
      else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    }).catch(error => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function handleUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    const fullFilePath = `resource/${account.owner}/${account.name}/${file.name}`;
    ResourceBackend.uploadResource(account.owner, account.name, "custom", "ResourceListPage", fullFilePath, file)
      .then(res => {
        if (res.status === "ok") { Setting.showMessage("success", i18next.t("application:File uploaded successfully")); fetchData({pagination}); }
        else Setting.showMessage("error", res.msg);
      }).finally(() => { setUploading(false); if (fileInputRef.current) fileInputRef.current.value = ""; });
  }

  function handlePageChange(page) { const np = {...pagination, current: page}; setPagination(np); fetchData({pagination: np}); }

  if (!isAuthorized) { return (<div className="flex flex-col items-center justify-center py-20"><h1 className="text-2xl font-bold text-white mb-2">403 Unauthorized</h1><a href="/"><Button>{i18next.t("general:Back Home")}</Button></a></div>); }
  const totalPages = Math.ceil(pagination.total / pagination.pageSize);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Resources")}</h2>
        <div className="flex items-center gap-2">
          <span className="text-sm text-zinc-400">{i18next.t("general:{total} in total").replace("{total}", String(pagination.total))}</span>
          <input ref={fileInputRef} type="file" className="hidden" onChange={handleUpload} />
          <Button size="sm" disabled={uploading} onClick={() => fileInputRef.current?.click()}>
            <Upload className="w-4 h-4 mr-1" />{uploading ? "Uploading..." : i18next.t("resource:Upload a file...")}
          </Button>
        </div>
      </div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800 bg-zinc-900/50">
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Provider")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Organization")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:User")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Name")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Created time")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Type")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("resource:File size")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:URL")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Action")}</th>
            </tr></thead>
            <tbody>
              {loading ? (<tr><td colSpan={9} className="px-4 py-8 text-center text-zinc-500">Loading...</td></tr>) :
               data.length === 0 ? (<tr><td colSpan={9} className="px-4 py-8 text-center text-zinc-500">No data</td></tr>) :
               data.map((record, index) => (
                <tr key={record.name} className="border-b border-zinc-800/50 hover:bg-zinc-900/30">
                  <td className="px-4 py-3"><Link to={`/providers/${record.owner}/${record.provider}`} className="text-blue-400 hover:text-blue-300">{record.provider}</Link></td>
                  <td className="px-4 py-3"><Link to={`/organizations/${record.owner}`} className="text-blue-400 hover:text-blue-300">{record.owner}</Link></td>
                  <td className="px-4 py-3"><Link to={`/users/${record.owner}/${record.user}`} className="text-blue-400 hover:text-blue-300">{record.user}</Link></td>
                  <td className="px-4 py-3 text-zinc-300">{record.name}</td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.fileType}</td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFriendlyFileSize(record.fileSize)}</td>
                  <td className="px-4 py-3">
                    <Button variant="outline" size="sm" onClick={() => { copy(record.url); Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully")); }}>
                      <Copy className="w-3 h-3 mr-1" />{i18next.t("resource:Copy Link")}
                    </Button>
                  </td>
                  <td className="px-4 py-3">
                    <Button variant="destructive" size="sm" onClick={() => { if (window.confirm(`${i18next.t("general:Sure to delete")}: ${record.name} ?`)) deleteResource(index); }}>
                      <Trash2 className="w-3 h-3 mr-1" />{i18next.t("general:Delete")}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {totalPages > 1 && (
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={pagination.current <= 1} onClick={() => handlePageChange(pagination.current - 1)}><ChevronLeft className="w-4 h-4" /></Button>
          <span className="text-sm text-zinc-400">{pagination.current} / {totalPages}</span>
          <Button variant="outline" size="sm" disabled={pagination.current >= totalPages} onClick={() => handlePageChange(pagination.current + 1)}><ChevronRight className="w-4 h-4" /></Button>
        </div>
      )}
    </div>
  );
}

export default ResourceListPage;

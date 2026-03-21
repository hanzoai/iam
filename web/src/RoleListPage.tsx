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

import React, {useEffect, useState, useCallback, useRef} from "react";
import {Link} from "react-router-dom";
import {Plus, Pencil, Trash2, ChevronLeft, ChevronRight, Upload, Download} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as RoleBackend from "./backend/RoleBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";
import * as XLSX from "xlsx";

interface RoleListPageProps {
  account: any;
  history: any;
  match: any;
}

function RoleListPage(props: RoleListPageProps) {
  const {account, history} = props;
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 10, total: 0});
  const [searchText, setSearchText] = useState("");
  const [searchedColumn, setSearchedColumn] = useState("");
  const [isAuthorized, setIsAuthorized] = useState(true);

  const fetchData = useCallback((params: any = {}) => {
    let field = params.searchedColumn || searchedColumn;
    let value = params.searchText || searchText;
    const sf = params.sortField || "";
    const so = params.sortOrder || "";
    const pag = params.pagination || pagination;
    if (params.type !== undefined && params.type !== null) { field = "type"; value = params.type; }

    setLoading(true);
    RoleBackend.getRoles(Setting.isDefaultOrganizationSelected(account) ? "" : Setting.getRequestOrganization(account), pag.current, pag.pageSize, field, value, sf, so)
      .then((res: any) => {
        setLoading(false);
        if (res.status === "ok") {
          setData(res.data || []);
          setPagination({...pag, total: res.data2});
          if (params.searchText !== undefined) setSearchText(params.searchText);
          if (params.searchedColumn !== undefined) setSearchedColumn(params.searchedColumn);
        } else {
          if (Setting.isResponseDenied(res)) setIsAuthorized(false);
          else Setting.showMessage("error", res.msg);
        }
      });
  }, [account, searchText, searchedColumn, pagination]);

  useEffect(() => { fetchData({pagination: {current: 1, pageSize: 10, total: 0}}); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function addRole() {
    const randomName = Setting.getRandomName();
    const owner = Setting.getRequestOrganization(account);
    const newRole = {
      owner, name: `role_${randomName}`, createdTime: moment().format(),
      displayName: `New Role - ${randomName}`, users: [], groups: [], roles: [], domains: [], isEnabled: true,
    };
    RoleBackend.addRole(newRole).then((res: any) => {
      if (res.status === "ok") {
        history.push({pathname: `/roles/${newRole.owner}/${newRole.name}`, mode: "add"});
        Setting.showMessage("success", i18next.t("general:Successfully added"));
      } else Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`));
  }

  function deleteRole(i: number) {
    RoleBackend.deleteRole(data[i]).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully deleted"));
        fetchData({pagination: {...pagination, current: pagination.current > 1 && data.length === 1 ? pagination.current - 1 : pagination.current}});
      } else Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
    });
  }

  function generateDownloadTemplate() {
    const roleObj: any = {};
    Setting.getRoleColumns().forEach((item: string) => { roleObj[item] = null; });
    const worksheet = XLSX.utils.json_to_sheet([roleObj]);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Sheet1");
    XLSX.writeFile(workbook, "import-role.xlsx", {compression: true});
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    fetch(`${Setting.ServerUrl}/api/upload-roles`, {
      method: "post", body: formData, credentials: "include",
      headers: {"Accept-Language": Setting.getAcceptLanguage()},
    }).then(res => res.json()).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", "Roles uploaded successfully, refreshing the page");
        fetchData({pagination});
      } else Setting.showMessage("error", `${i18next.t("general:Failed to upload")}: ${res.msg}`);
    }).catch((error: any) => Setting.showMessage("error", `${i18next.t("general:Failed to upload")}: ${error.message}`));
    e.target.value = "";
  }

  function handlePageChange(page: number) {
    const newPag = {...pagination, current: page};
    setPagination(newPag);
    fetchData({pagination: newPag});
  }

  if (!isAuthorized) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <h1 className="text-2xl font-bold text-white mb-2">403 Unauthorized</h1>
        <p className="text-zinc-400 mb-4">{i18next.t("general:Sorry, you do not have permission to access this page or logged in status invalid.")}</p>
        <a href="/"><Button>{i18next.t("general:Back Home")}</Button></a>
      </div>
    );
  }

  const totalPages = Math.ceil(pagination.total / pagination.pageSize);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Roles")}</h2>
        <div className="flex items-center gap-2">
          <span className="text-sm text-zinc-400">{i18next.t("general:{total} in total").replace("{total}", String(pagination.total))}</span>
          <Button size="sm" onClick={addRole}><Plus className="w-4 h-4 mr-1" />{i18next.t("general:Add")}</Button>
          <Button variant="outline" size="sm" onClick={generateDownloadTemplate}><Download className="w-4 h-4 mr-1" />{i18next.t("general:Download template")}</Button>
          <input ref={fileInputRef} type="file" accept=".xlsx" className="hidden" onChange={handleFileUpload} />
          <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}><Upload className="w-4 h-4 mr-1" />{i18next.t("general:Upload (.xlsx)")}</Button>
        </div>
      </div>

      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/50">
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Name")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Organization")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Created time")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Display name")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("role:Sub users")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("role:Sub groups")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("role:Sub roles")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("role:Sub domains")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Is enabled")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={10} className="px-4 py-8 text-center text-zinc-500">Loading...</td></tr>
              ) : data.length === 0 ? (
                <tr><td colSpan={10} className="px-4 py-8 text-center text-zinc-500">No data</td></tr>
              ) : data.map((record, index) => (
                <tr key={`${record.owner}/${record.name}`} className="border-b border-zinc-800/50 hover:bg-zinc-900/30">
                  <td className="px-4 py-3"><Link to={`/roles/${record.owner}/${encodeURIComponent(record.name)}`} className="text-blue-400 hover:text-blue-300">{record.name}</Link></td>
                  <td className="px-4 py-3"><Link to={`/organizations/${record.owner}`} className="text-blue-400 hover:text-blue-300">{record.owner}</Link></td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.displayName}</td>
                  <td className="px-4 py-3 text-zinc-300">{(record.users || []).map((u: string) => <span key={u} className="inline-block bg-zinc-800 px-2 py-0.5 rounded text-xs mr-1 mb-1">{u}</span>)}</td>
                  <td className="px-4 py-3 text-zinc-300">{(record.groups || []).map((g: string) => <span key={g} className="inline-block bg-zinc-800 px-2 py-0.5 rounded text-xs mr-1 mb-1">{g}</span>)}</td>
                  <td className="px-4 py-3 text-zinc-300">{(record.roles || []).map((r: string) => <span key={r} className="inline-block bg-zinc-800 px-2 py-0.5 rounded text-xs mr-1 mb-1">{r}</span>)}</td>
                  <td className="px-4 py-3 text-zinc-300">{(record.domains || []).map((d: string) => <span key={d} className="inline-block bg-zinc-800 px-2 py-0.5 rounded text-xs mr-1 mb-1">{d}</span>)}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs ${record.isEnabled ? "bg-green-900/50 text-green-400" : "bg-zinc-800 text-zinc-500"}`}>{record.isEnabled ? i18next.t("general:ON") : i18next.t("general:OFF")}</span></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Button size="sm" onClick={() => history.push(`/roles/${record.owner}/${encodeURIComponent(record.name)}`)}><Pencil className="w-3 h-3 mr-1" />{i18next.t("general:Edit")}</Button>
                      <Button variant="destructive" size="sm" onClick={() => { if (window.confirm(`${i18next.t("general:Sure to delete")}: ${record.name} ?`)) deleteRole(index); }}>
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

export default RoleListPage;

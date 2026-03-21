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

import React, {useEffect, useState, useCallback} from "react";
import {Link} from "react-router-dom";
import {ChevronLeft, ChevronRight, Eye, X} from "lucide-react";
import * as Setting from "./Setting";
import * as RecordBackend from "./backend/RecordBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";

function RecordListPage(props) {
  const {account} = props;
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 20, total: 0});
  const [isAuthorized, setIsAuthorized] = useState(true);
  const [detailRecord, setDetailRecord] = useState(null);

  const fetchData = useCallback((params = {}) => {
    let field = params.searchedColumn || "";
    let value = params.searchText || "";
    const sf = params.sortField || "";
    const so = params.sortOrder || "";
    const pag = params.pagination || pagination;
    if (params.method !== undefined && params.method !== null) { field = "method"; value = params.method; }
    setLoading(true);
    RecordBackend.getRecords(Setting.isDefaultOrganizationSelected(account) ? "" : Setting.getRequestOrganization(account), pag.current, pag.pageSize, field, value, sf, so)
      .then((res) => {
        setLoading(false);
        if (res.status === "ok") { setData(res.data || []); setPagination({...pag, total: res.data2}); setDetailRecord(null); }
        else { if (res.data?.includes("Please login first")) setIsAuthorized(false); }
      });
  }, [account, pagination]);

  useEffect(() => { fetchData({pagination: {current: 1, pageSize: 20, total: 0}}); }, []);

  function handlePageChange(page) { const np = {...pagination, current: page}; setPagination(np); fetchData({pagination: np}); }

  function jsonStrFormatter(str) {
    try { return JSON.stringify(JSON.parse(str), null, 2); }
    catch { return str; }
  }

  if (!isAuthorized) { return (<div className="flex flex-col items-center justify-center py-20"><h1 className="text-2xl font-bold text-white mb-2">403 Unauthorized</h1><a href="/"><Button>{i18next.t("general:Back Home")}</Button></a></div>); }
  const totalPages = Math.ceil(pagination.total / pagination.pageSize);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Records")}</h2>
        <span className="text-sm text-zinc-400">{i18next.t("general:{total} in total").replace("{total}", String(pagination.total))}</span>
      </div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800 bg-zinc-900/50">
              {!Setting.isLocalAdminUser(account) && <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Name")}</th>}
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:ID")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Client IP")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Timestamp")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Organization")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:User")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Method")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Request URI")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Action")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("record:Is triggered")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Detail")}</th>
            </tr></thead>
            <tbody>
              {loading ? (<tr><td colSpan={11} className="px-4 py-8 text-center text-zinc-500">Loading...</td></tr>) :
               data.length === 0 ? (<tr><td colSpan={11} className="px-4 py-8 text-center text-zinc-500">No data</td></tr>) :
               data.map((record) => (
                <tr key={record.id} className="border-b border-zinc-800/50 hover:bg-zinc-900/30">
                  {!Setting.isLocalAdminUser(account) && <td className="px-4 py-3 text-zinc-300 max-w-[200px] truncate">{record.name}</td>}
                  <td className="px-4 py-3 text-zinc-300">{record.id}</td>
                  <td className="px-4 py-3"><a target="_blank" rel="noreferrer" href={`https://db-ip.com/${record.clientIp}`} className="text-blue-400 hover:text-blue-300">{record.clientIp}</a></td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3"><Link to={`/organizations/${record.organization}`} className="text-blue-400 hover:text-blue-300">{record.organization}</Link></td>
                  <td className="px-4 py-3"><Link to={`/users/${record.organization}/${record.user}`} className="text-blue-400 hover:text-blue-300">{record.user}</Link></td>
                  <td className="px-4 py-3 text-zinc-300">{record.method}</td>
                  <td className="px-4 py-3 text-zinc-300 max-w-[200px] truncate" title={record.requestUri}>{record.requestUri}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.action}</td>
                  <td className="px-4 py-3">{["signup", "login", "logout", "update-user", "new-user"].includes(record.action) && <span className={`px-2 py-0.5 rounded text-xs ${record.isTriggered ? "bg-green-900/50 text-green-400" : "bg-zinc-800 text-zinc-500"}`}>{record.isTriggered ? i18next.t("general:ON") : i18next.t("general:OFF")}</span>}</td>
                  <td className="px-4 py-3">
                    <Button variant="outline" size="sm" onClick={() => setDetailRecord(record)}><Eye className="w-3 h-3 mr-1" />{i18next.t("general:Detail")}</Button>
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
      {detailRecord && (
        <div className="fixed inset-0 z-50 flex justify-end" onClick={() => setDetailRecord(null)}>
          <div className="absolute inset-0 bg-black/50" />
          <div className="relative w-full max-w-[640px] bg-zinc-950 border-l border-zinc-800 h-full overflow-y-auto p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-white">{i18next.t("general:Detail")}</h3>
              <button className="text-zinc-400 hover:text-white" onClick={() => setDetailRecord(null)}><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4 text-sm">
              {[
                [i18next.t("general:ID"), detailRecord.id],
                [i18next.t("general:Client IP"), detailRecord.clientIp],
                [i18next.t("general:Timestamp"), detailRecord.createdTime],
                [i18next.t("general:Method"), detailRecord.method],
                [i18next.t("general:Request URI"), detailRecord.requestUri],
                [i18next.t("user:Language"), detailRecord.language],
                [i18next.t("record:Status code"), detailRecord.statusCode],
                [i18next.t("general:Action"), detailRecord.action],
              ].map(([label, value]) => (
                <div key={label} className="grid grid-cols-[140px_1fr] gap-2 border-b border-zinc-800 pb-3">
                  <span className="text-zinc-400">{label}</span>
                  <span className="text-zinc-200">{value}</span>
                </div>
              ))}
              <div className="grid grid-cols-[140px_1fr] gap-2 border-b border-zinc-800 pb-3">
                <span className="text-zinc-400">{i18next.t("general:Organization")}</span>
                <Link to={`/organizations/${detailRecord.organization}`} className="text-blue-400 hover:text-blue-300">{detailRecord.organization}</Link>
              </div>
              <div className="grid grid-cols-[140px_1fr] gap-2 border-b border-zinc-800 pb-3">
                <span className="text-zinc-400">{i18next.t("general:User")}</span>
                <Link to={`/users/${detailRecord.organization}/${detailRecord.user}`} className="text-blue-400 hover:text-blue-300">{detailRecord.user}</Link>
              </div>
              <div className="border-b border-zinc-800 pb-3">
                <span className="text-zinc-400 block mb-2">{i18next.t("record:Response")}</span>
                <pre className="bg-zinc-900 rounded p-3 text-xs text-zinc-300 overflow-auto max-h-[200px] whitespace-pre-wrap">{detailRecord.response}</pre>
              </div>
              <div className="pb-3">
                <span className="text-zinc-400 block mb-2">{i18next.t("record:Object")}</span>
                <pre className="bg-zinc-900 rounded p-3 text-xs text-zinc-300 overflow-auto max-h-[300px] whitespace-pre-wrap">{jsonStrFormatter(detailRecord.object)}</pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default RecordListPage;

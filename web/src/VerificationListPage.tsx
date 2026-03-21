// @ts-nocheck
// Copyright 2024 The Hanzo Authors. All Rights Reserved.
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
import {ChevronLeft, ChevronRight} from "lucide-react";
import * as Setting from "./Setting";
import * as VerificationBackend from "./backend/VerificationBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";

function VerificationListPage(props) {
  const {account} = props;
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 10, total: 0});
  const [isAuthorized, setIsAuthorized] = useState(true);

  const fetchData = useCallback((params = {}) => {
    let field = params.searchedColumn || "";
    let value = params.searchText || "";
    const sf = params.sortField || "";
    const so = params.sortOrder || "";
    const pag = params.pagination || pagination;
    if (params.type !== undefined && params.type !== null) { field = "type"; value = params.type; }
    setLoading(true);
    VerificationBackend.getVerifications("", Setting.isDefaultOrganizationSelected(account) ? "" : Setting.getRequestOrganization(account), pag.current, pag.pageSize, field, value, sf, so)
      .then((res) => {
        setLoading(false);
        if (res.status === "ok") { setData(res.data || []); setPagination({...pag, total: res.data2}); }
        else { if (Setting.isResponseDenied(res)) setIsAuthorized(false); else Setting.showMessage("error", res.msg); }
      });
  }, [account, pagination]);

  useEffect(() => { fetchData({pagination: {current: 1, pageSize: 10, total: 0}}); }, []);

  function handlePageChange(page) { const np = {...pagination, current: page}; setPagination(np); fetchData({pagination: np}); }

  if (!isAuthorized) { return (<div className="flex flex-col items-center justify-center py-20"><h1 className="text-2xl font-bold text-white mb-2">403 Unauthorized</h1><a href="/"><Button>{i18next.t("general:Back Home")}</Button></a></div>); }
  const totalPages = Math.ceil(pagination.total / pagination.pageSize);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Verifications")}</h2>
        <span className="text-sm text-zinc-400">{i18next.t("general:{total} in total").replace("{total}", String(pagination.total))}</span>
      </div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800 bg-zinc-900/50">
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Organization")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Name")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Created time")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Type")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:User")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Provider")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Client IP")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("verification:Receiver")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("login:Verification code")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("verification:Is used")}</th>
            </tr></thead>
            <tbody>
              {loading ? (<tr><td colSpan={10} className="px-4 py-8 text-center text-zinc-500">Loading...</td></tr>) :
               data.length === 0 ? (<tr><td colSpan={10} className="px-4 py-8 text-center text-zinc-500">No data</td></tr>) :
               data.map((record) => (
                <tr key={`${record.owner}/${record.name}`} className="border-b border-zinc-800/50 hover:bg-zinc-900/30">
                  <td className="px-4 py-3">{record.owner === "admin" ? `(${i18next.t("general:empty")})` : <Link to={`/organizations/${record.owner}`} className="text-blue-400 hover:text-blue-300">{record.owner}</Link>}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.name}</td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.type}</td>
                  <td className="px-4 py-3"><Link to={`/users/${record.user}`} className="text-blue-400 hover:text-blue-300">{record.user}</Link></td>
                  <td className="px-4 py-3"><Link to={`/providers/${record.owner}/${record.provider}`} className="text-blue-400 hover:text-blue-300">{record.provider}</Link></td>
                  <td className="px-4 py-3"><a target="_blank" rel="noreferrer" href={`https://db-ip.com/${record.remoteAddr?.replace(/: $/, "")}`} className="text-blue-400 hover:text-blue-300">{record.remoteAddr?.replace(/: $/, "")}</a></td>
                  <td className="px-4 py-3 text-zinc-300">{record.receiver}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.code}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs ${record.isUsed ? "bg-green-900/50 text-green-400" : "bg-zinc-800 text-zinc-500"}`}>{record.isUsed ? i18next.t("general:ON") : i18next.t("general:OFF")}</span></td>
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

export default VerificationListPage;

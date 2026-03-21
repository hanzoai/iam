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
import {Plus, Pencil, Trash2, ChevronLeft, ChevronRight} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as TokenBackend from "./backend/TokenBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";

interface TokenListPageProps {
  account: any;
  history: any;
  match: any;
}

function TokenListPage(props: TokenListPageProps) {
  const {account, history} = props;

  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 10, total: 0});
  const [searchText, setSearchText] = useState("");
  const [searchedColumn, setSearchedColumn] = useState("");
  const [isAuthorized, setIsAuthorized] = useState(true);

  const fetchData = useCallback((params: any = {}) => {
    const field = params.searchedColumn || searchedColumn;
    const value = params.searchText || searchText;
    const sf = params.sortField || "";
    const so = params.sortOrder || "";
    const pag = params.pagination || pagination;

    setLoading(true);
    TokenBackend.getTokens("admin", Setting.isDefaultOrganizationSelected(account) ? "" : Setting.getRequestOrganization(account), pag.current, pag.pageSize, field, value, sf, so)
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

  useEffect(() => {
    fetchData({pagination: {current: 1, pageSize: 10, total: 0}});
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function addToken() {
    const randomName = Setting.getRandomName();
    const organizationName = Setting.getRequestOrganization(account);
    const newToken = {
      owner: "admin", name: `token_${randomName}`, createdTime: moment().format(),
      application: "app-hanzo", organization: organizationName, user: "admin",
      accessToken: "", expiresIn: 7200, scope: "read", tokenType: "Bearer",
    };
    TokenBackend.addToken(newToken).then((res: any) => {
      if (res.status === "ok") {
        history.push({pathname: `/tokens/${newToken.name}`, mode: "add"});
        Setting.showMessage("success", i18next.t("general:Successfully added"));
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
      }
    }).catch((error: any) => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
  }

  function deleteToken(i: number) {
    TokenBackend.deleteToken(data[i]).then((res: any) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully deleted"));
        fetchData({pagination: {...pagination, current: pagination.current > 1 && data.length === 1 ? pagination.current - 1 : pagination.current}});
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
      }
    }).catch((error: any) => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
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
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Tokens")}</h2>
        <div className="flex items-center gap-2">
          <span className="text-sm text-zinc-400">{i18next.t("general:{total} in total").replace("{total}", String(pagination.total))}</span>
          <Button size="sm" onClick={addToken}><Plus className="w-4 h-4 mr-1" />{i18next.t("general:Add")}</Button>
        </div>
      </div>

      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/50">
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Name")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Created time")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Application")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Organization")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:User")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("token:Authorization code")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("token:Access token")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("token:Expires in")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("provider:Scope")}</th>
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
                  <td className="px-4 py-3"><Link to={`/tokens/${record.name}`} className="text-blue-400 hover:text-blue-300">{record.name}</Link></td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3"><Link to={`/applications/${record.organization}/${record.application}`} className="text-blue-400 hover:text-blue-300">{record.application}</Link></td>
                  <td className="px-4 py-3"><Link to={`/organizations/${record.organization}`} className="text-blue-400 hover:text-blue-300">{record.organization}</Link></td>
                  <td className="px-4 py-3"><Link to={`/users/${record.organization}/${record.user}`} className="text-blue-400 hover:text-blue-300">{record.user}</Link></td>
                  <td className="px-4 py-3 text-zinc-300 max-w-[180px] truncate">{record.code}</td>
                  <td className="px-4 py-3 text-zinc-300 max-w-[220px] truncate">{record.accessToken}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.expiresIn}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.scope}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Button size="sm" onClick={() => history.push(`/tokens/${record.name}`)}><Pencil className="w-3 h-3 mr-1" />{i18next.t("general:Edit")}</Button>
                      <Button variant="destructive" size="sm" onClick={() => { if (window.confirm(`${i18next.t("general:Sure to delete")}: ${record.name} ?`)) deleteToken(index); }}>
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

export default TokenListPage;

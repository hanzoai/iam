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
import {Plus, Pencil, Trash2, RefreshCw, Search, ChevronLeft, ChevronRight} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as CertBackend from "./backend/CertBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";

interface CertListPageProps {
  account: any;
  history: any;
  match: any;
}

function CertListPage(props: CertListPageProps) {
  const {account, history} = props;

  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 10, total: 0});
  const [searchText, setSearchText] = useState("");
  const [searchedColumn, setSearchedColumn] = useState("");
  const [isAuthorized, setIsAuthorized] = useState(true);
  const [sortField, setSortField] = useState("");
  const [sortOrder, setSortOrder] = useState("");

  const fetchData = useCallback((params: any = {}) => {
    let field = params.searchedColumn || searchedColumn;
    let value = params.searchText || searchText;
    const sf = params.sortField || sortField;
    const so = params.sortOrder || sortOrder;
    const pag = params.pagination || pagination;

    if (params.category !== undefined && params.category !== null) {
      field = "category";
      value = params.category;
    } else if (params.type !== undefined && params.type !== null) {
      field = "type";
      value = params.type;
    }

    setLoading(true);
    const fetchFn = Setting.isDefaultOrganizationSelected(account)
      ? CertBackend.getGlobalCerts(pag.current, pag.pageSize, field, value, sf, so)
      : CertBackend.getCerts(Setting.getRequestOrganization(account), pag.current, pag.pageSize, field, value, sf, so);

    fetchFn.then((res: any) => {
      setLoading(false);
      if (res.status === "ok") {
        setData(res.data || []);
        setPagination({...pag, total: res.data2});
        if (params.searchText !== undefined) setSearchText(params.searchText);
        if (params.searchedColumn !== undefined) setSearchedColumn(params.searchedColumn);
      } else {
        if (Setting.isResponseDenied(res)) {
          setIsAuthorized(false);
        } else {
          Setting.showMessage("error", res.msg);
        }
      }
    });
  }, [account, searchText, searchedColumn, sortField, sortOrder, pagination]);

  useEffect(() => {
    fetchData({pagination: {current: 1, pageSize: 10, total: 0}});
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function newCert() {
    const randomName = Setting.getRandomName();
    const owner = Setting.isDefaultOrganizationSelected(account)
      ? (Setting.isAdminUser(account) ? "admin" : account.owner)
      : Setting.getRequestOrganization(account);
    return {
      owner, name: `cert_${randomName}`, createdTime: moment().format(),
      displayName: `New Cert - ${randomName}`, scope: "JWT", type: "x509",
      cryptoAlgorithm: "RS256", bitSize: 4096, expireInYears: 20,
      certificate: "", privateKey: "",
    };
  }

  function addCert() {
    const cert = newCert();
    CertBackend.addCert(cert).then((res: any) => {
      if (res.status === "ok") {
        history.push({pathname: `/certs/${cert.owner}/${cert.name}`, mode: "add"});
        Setting.showMessage("success", i18next.t("general:Successfully added"));
      } else {
        Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
      }
    }).catch((error: any) => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
  }

  function deleteCert(i: number) {
    CertBackend.deleteCert(data[i]).then((res: any) => {
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

  function refreshCert(i: number) {
    const cert = data[i];
    CertBackend.refreshDomainExpire(cert.owner, cert.name).then((res: any) => {
      if (res.status === "error") {
        Setting.showMessage("error", `Failed to refresh domain expire: ${res.msg}`);
      } else {
        Setting.showMessage("success", "Domain expire refreshed successfully");
        fetchData({pagination});
      }
    }).catch((error: any) => {
      Setting.showMessage("error", `Domain expire failed to refresh: ${error}`);
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
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Certs")}</h2>
        <div className="flex items-center gap-2">
          <span className="text-sm text-zinc-400">
            {i18next.t("general:{total} in total").replace("{total}", String(pagination.total))}
          </span>
          <Button size="sm" onClick={addCert}>
            <Plus className="w-4 h-4 mr-1" />
            {i18next.t("general:Add")}
          </Button>
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
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("provider:Scope")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Type")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("cert:Crypto algorithm")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("cert:Bit size")}</th>
                <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("cert:Expire in years")}</th>
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
                  <td className="px-4 py-3">
                    <Link to={`/certs/${record.owner}/${record.name}`} className="text-blue-400 hover:text-blue-300">{record.name}</Link>
                  </td>
                  <td className="px-4 py-3 text-zinc-300">{record.owner !== "admin" ? record.owner : i18next.t("provider:admin (Shared)")}</td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.displayName}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.scope}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.type}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.cryptoAlgorithm}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.bitSize}</td>
                  <td className="px-4 py-3 text-zinc-300">{record.expireInYears}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {record.type === "SSL" && (
                        <Button variant="outline" size="sm" disabled={!Setting.isAdminUser(account) && record.owner !== account.owner} onClick={() => refreshCert(index)}>
                          <RefreshCw className="w-3 h-3 mr-1" />{i18next.t("general:Refresh")}
                        </Button>
                      )}
                      <Button size="sm" disabled={!Setting.isAdminUser(account) && record.owner !== account.owner} onClick={() => history.push(`/certs/${record.owner}/${record.name}`)}>
                        <Pencil className="w-3 h-3 mr-1" />{i18next.t("general:Edit")}
                      </Button>
                      <Button variant="destructive" size="sm" disabled={!Setting.isAdminUser(account) && record.owner !== account.owner} onClick={() => {
                        if (window.confirm(`${i18next.t("general:Sure to delete")}: ${record.name} ?`)) deleteCert(index);
                      }}>
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
          <Button variant="outline" size="sm" disabled={pagination.current <= 1} onClick={() => handlePageChange(pagination.current - 1)}>
            <ChevronLeft className="w-4 h-4" />
          </Button>
          <span className="text-sm text-zinc-400">{pagination.current} / {totalPages}</span>
          <Button variant="outline" size="sm" disabled={pagination.current >= totalPages} onClick={() => handlePageChange(pagination.current + 1)}>
            <ChevronRight className="w-4 h-4" />
          </Button>
        </div>
      )}
    </div>
  );
}

export default CertListPage;

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
import {Plus, Pencil, Trash2, ChevronLeft, ChevronRight} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as RuleBackend from "./backend/RuleBackend";
import i18next from "i18next";
import {Button} from "./components/ui/button";

function RuleListPage(props) {
  const {account, history} = props;
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({current: 1, pageSize: 10, total: 0});

  const fetchData = useCallback((params = {}) => {
    const sf = params.sortField || "";
    const so = params.sortOrder || "";
    const pag = params.pagination || pagination;
    setLoading(true);
    RuleBackend.getRules(account.owner, pag.current, pag.pageSize, sf, so).then((res) => {
      setLoading(false);
      if (res.status === "ok") { setData(res.data || []); setPagination({...pag, total: res.data2}); }
    });
  }, [account, pagination]);

  useEffect(() => { fetchData({pagination: {current: 1, pageSize: 10, total: 0}}); }, []);

  function addRule() {
    const randomName = Setting.getRandomName();
    const owner = Setting.getRequestOrganization(account);
    const r = {owner, name: `rule_${randomName}`, createdTime: moment().format(), type: "User-Agent", expressions: [], action: "Block", reason: "Your request is blocked."};
    RuleBackend.addRule(r).then((res) => {
      if (res.status === "error") Setting.showMessage("error", `Failed to add: ${res.msg}`);
      else { Setting.showMessage("success", "Rule added successfully"); fetchData(); }
    });
  }

  function deleteRule(i) {
    RuleBackend.deleteRule(data[i]).then((res) => {
      if (res.status === "error") Setting.showMessage("error", `Failed to delete: ${res.msg}`);
      else { Setting.showMessage("success", "Deleted successfully"); fetchData({pagination: {...pagination, current: pagination.current > 1 && data.length === 1 ? pagination.current - 1 : pagination.current}}); }
    });
  }

  function handlePageChange(page) { const np = {...pagination, current: page}; setPagination(np); fetchData({pagination: np}); }
  const totalPages = Math.ceil(pagination.total / pagination.pageSize);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">{i18next.t("general:Rules")}</h2>
        <div className="flex items-center gap-2">
          <span className="text-sm text-zinc-400">{i18next.t("general:{total} in total").replace("{total}", String(pagination.total))}</span>
          <Button size="sm" onClick={addRule}><Plus className="w-4 h-4 mr-1" />{i18next.t("general:Add")}</Button>
        </div>
      </div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-zinc-800 bg-zinc-900/50">
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Owner")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Name")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Create time")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("rule:Type")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("rule:Expressions")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Action")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("rule:Reason")}</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">{i18next.t("general:Action")}</th>
            </tr></thead>
            <tbody>
              {loading ? (<tr><td colSpan={8} className="px-4 py-8 text-center text-zinc-500">Loading...</td></tr>) :
               data.length === 0 ? (<tr><td colSpan={8} className="px-4 py-8 text-center text-zinc-500">No data</td></tr>) :
               data.map((record, index) => (
                <tr key={record.name} className="border-b border-zinc-800/50 hover:bg-zinc-900/30">
                  <td className="px-4 py-3 text-zinc-300">{record.owner}</td>
                  <td className="px-4 py-3"><a href={`/rules/${record.owner}/${record.name}`} className="text-blue-400 hover:text-blue-300">{record.name}</a></td>
                  <td className="px-4 py-3 text-zinc-300">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3"><span className="px-2 py-0.5 rounded text-xs bg-blue-900/50 text-blue-400">{i18next.t(`rule:${record.type}`)}</span></td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {record.expressions?.map((expr, i) => (
                        <span key={i} className="px-2 py-0.5 rounded text-xs bg-green-900/50 text-green-400">{expr.operator} {expr.value?.slice(0, 20)}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-zinc-300">{record.action}</td>
                  <td className="px-4 py-3 text-zinc-300 max-w-[200px] truncate">{record.reason}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Button variant="outline" size="sm" onClick={() => history.push(`/rules/${record.owner}/${record.name}`)}><Pencil className="w-3 h-3 mr-1" />{i18next.t("general:Edit")}</Button>
                      <Button variant="destructive" size="sm" onClick={() => { if (window.confirm(`Sure to delete rule: ${record.name} ?`)) deleteRule(index); }}>
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

export default RuleListPage;

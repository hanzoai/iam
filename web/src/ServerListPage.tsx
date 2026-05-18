// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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

// @ts-nocheck
import React from "react";
import {Link} from "react-router-dom";
import moment from "moment";
import * as Setting from "./Setting";
import * as ServerBackend from "./backend/ServerBackend";
import i18next from "i18next";
import BaseListPage from "./BaseListPage";
import PopconfirmModal from "./common/modal/PopconfirmModal";
import {Button} from "./components/ui/button";
import {Spinner} from "./components/ui/spinner";

class ServerListPage extends BaseListPage {
  newServer() {
    const randomName = Setting.getRandomName();
    const owner = Setting.getRequestOrganization(this.props.account);
    return {
      owner: owner,
      name: `server_${randomName}`,
      createdTime: moment().format(),
      displayName: `New Server - ${randomName}`,
      url: "",
      application: "",
    };
  }

  addServer() {
    const newServer = this.newServer();
    ServerBackend.addServer(newServer)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/servers/${newServer.owner}/${newServer.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteServer(i) {
    ServerBackend.deleteServer(this.state.data[i])
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          this.fetch({
            pagination: {
              ...this.state.pagination,
              current: this.state.pagination.current > 1 && this.state.data.length === 1 ? this.state.pagination.current - 1 : this.state.pagination.current,
            },
          });
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  fetch = (params = {}) => {
    const field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (!params.pagination) {
      params.pagination = {current: 1, pageSize: 10};
    }

    this.setState({loading: true});
    ServerBackend.getServers(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
      .then((res) => {
        this.setState({loading: false});
        if (res.status === "ok") {
          this.setState({
            data: res.data,
            pagination: {
              ...params.pagination,
              total: res.data2,
            },
            searchText: params.searchText,
            searchedColumn: params.searchedColumn,
          });
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${res.msg}`);
        }
      });
  };

  renderTable(servers) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold">{i18next.t("server:Edit MCP Server")}</h2>
          <Button size="sm" onClick={() => this.addServer()}>{i18next.t("general:Add")}</Button>
        </div>

        <div className="overflow-x-auto border border-border rounded-md">
          <table className="w-full text-sm">
            <thead className="bg-muted/40">
              <tr>
                <th className="px-4 py-2 text-left font-medium" style={{width: "160px"}}>{i18next.t("general:Name")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "130px"}}>{i18next.t("general:Organization")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "180px"}}>{i18next.t("general:Created time")}</th>
                <th className="px-4 py-2 text-left font-medium">{i18next.t("general:Display name")}</th>
                <th className="px-4 py-2 text-left font-medium">{i18next.t("general:URL")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "140px"}}>{i18next.t("general:Application")}</th>
                <th className="px-4 py-2 text-right font-medium" style={{width: "180px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {this.state.loading && (
                <tr><td colSpan={7} className="px-4 py-10 text-center"><Spinner size="lg" /></td></tr>
              )}
              {!this.state.loading && servers?.map((record, index) => (
                <tr key={`${record.owner}/${record.name}`} className="border-t border-border hover:bg-muted/20">
                  <td className="px-4 py-2"><Link to={`/servers/${record.owner}/${record.name}`}>{record.name}</Link></td>
                  <td className="px-4 py-2">{record.owner}</td>
                  <td className="px-4 py-2 text-muted-foreground">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-2">{record.displayName}</td>
                  <td className="px-4 py-2">
                    {record.url ? (
                      <a target="_blank" rel="noreferrer" href={record.url}>{Setting.getShortText(record.url, 40)}</a>
                    ) : null}
                  </td>
                  <td className="px-4 py-2">{record.application}</td>
                  <td className="px-4 py-2 text-right">
                    <div className="inline-flex gap-2">
                      <Button size="sm" onClick={() => this.props.history.push(`/servers/${record.owner}/${record.name}`)}>{i18next.t("general:Edit")}</Button>
                      <PopconfirmModal title={i18next.t("general:Sure to delete") + `: ${record.name} ?`} onConfirm={() => this.deleteServer(index)} />
                    </div>
                  </td>
                </tr>
              ))}
              {!this.state.loading && (!servers || servers.length === 0) && (
                <tr><td colSpan={7} className="px-4 py-10 text-center text-muted-foreground">{i18next.t("general:No data")}</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>{i18next.t("general:{total} in total").replace("{total}", this.state.pagination.total ?? 0)}</span>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" disabled={this.state.pagination.current <= 1}
              onClick={() => this.handleTableChange({...this.state.pagination, current: this.state.pagination.current - 1}, {}, {})}>Prev</Button>
            <span>{this.state.pagination.current}</span>
            <Button variant="outline" size="sm"
              disabled={this.state.pagination.current * this.state.pagination.pageSize >= (this.state.pagination.total ?? 0)}
              onClick={() => this.handleTableChange({...this.state.pagination, current: this.state.pagination.current + 1}, {}, {})}>Next</Button>
          </div>
        </div>
      </div>
    );
  }
}

export default ServerListPage;

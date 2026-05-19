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
import * as KeyBackend from "./backend/KeyBackend";
import i18next from "i18next";
import BaseListPage from "./BaseListPage";
import PopconfirmModal from "./common/modal/PopconfirmModal";
import {Button} from "./components/ui/button";
import {Spinner} from "./components/ui/spinner";

class KeyListPage extends BaseListPage {
  newKey() {
    const randomName = Setting.getRandomName();
    const owner = Setting.getRequestOrganization(this.props.account);
    return {
      owner: owner,
      name: `key_${randomName}`,
      createdTime: moment().format(),
      updatedTime: moment().format(),
      displayName: `New Key - ${randomName}`,
      type: "Organization",
      organization: owner,
      application: "",
      user: "",
      accessKey: "",
      accessSecret: "",
      expireTime: "",
      state: "Active",
    };
  }

  addKey() {
    const newKey = this.newKey();
    KeyBackend.addKey(newKey)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/keys/${newKey.owner}/${newKey.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteKey(i) {
    KeyBackend.deleteKey(this.state.data[i])
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

  renderTable(keys) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold">{i18next.t("general:Keys")}</h2>
          <Button size="sm" onClick={this.addKey.bind(this)}>{i18next.t("general:Add")}</Button>
        </div>

        <div className="overflow-x-auto border border-border rounded-md">
          <table className="w-full text-sm">
            <thead className="bg-muted/40">
              <tr>
                <th className="px-4 py-2 text-left font-medium" style={{width: "140px"}}>{i18next.t("general:Name")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "150px"}}>{i18next.t("general:Organization")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "160px"}}>{i18next.t("general:Created time")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "170px"}}>{i18next.t("general:Display name")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "140px"}}>{i18next.t("general:Type")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "300px"}}>{i18next.t("key:Access key")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "160px"}}>{i18next.t("general:Expire time")}</th>
                <th className="px-4 py-2 text-left font-medium" style={{width: "120px"}}>{i18next.t("general:State")}</th>
                <th className="px-4 py-2 text-right font-medium" style={{width: "180px"}}>{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {this.state.loading && (
                <tr><td colSpan={9} className="px-4 py-10 text-center"><Spinner size="lg" /></td></tr>
              )}
              {!this.state.loading && keys?.map((record, index) => (
                <tr key={`${record.owner}/${record.name}`} className="border-t border-border hover:bg-muted/20">
                  <td className="px-4 py-2"><Link to={`/keys/${record.owner}/${record.name}`}>{record.name}</Link></td>
                  <td className="px-4 py-2"><Link to={`/organizations/${record.owner}`}>{record.owner}</Link></td>
                  <td className="px-4 py-2 text-muted-foreground">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-2">{record.displayName}</td>
                  <td className="px-4 py-2">{record.type}</td>
                  <td className="px-4 py-2 font-mono text-xs">{record.accessKey}</td>
                  <td className="px-4 py-2 text-muted-foreground">{Setting.getFormattedDate(record.expireTime)}</td>
                  <td className="px-4 py-2">{record.state}</td>
                  <td className="px-4 py-2 text-right">
                    <div className="inline-flex gap-2">
                      <Button size="sm" onClick={() => this.props.history.push(`/keys/${record.owner}/${record.name}`)}>{i18next.t("general:Edit")}</Button>
                      <PopconfirmModal title={i18next.t("general:Sure to delete") + `: ${record.name} ?`} onConfirm={() => this.deleteKey(index)} />
                    </div>
                  </td>
                </tr>
              ))}
              {!this.state.loading && (!keys || keys.length === 0) && (
                <tr><td colSpan={9} className="px-4 py-10 text-center text-muted-foreground">{i18next.t("general:No data")}</td></tr>
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

  fetch = (params = {}) => {
    let field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (params.type !== undefined && params.type !== null) {
      field = "type";
      value = params.type;
    }
    this.setState({loading: true});
    (Setting.isDefaultOrganizationSelected(this.props.account) ? KeyBackend.getGlobalKeys(params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
      : KeyBackend.getKeys(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder))
      .then((res) => {
        this.setState({
          loading: false,
        });
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
          if (Setting.isResponseDenied(res)) {
            this.setState({
              isAuthorized: false,
            });
          } else {
            Setting.showMessage("error", res.msg);
          }
        }
      });
  };
}

export default KeyListPage;

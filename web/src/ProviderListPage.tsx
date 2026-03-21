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

// @ts-nocheck
import React from "react";
import {Link} from "react-router-dom";
import {Pencil} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as ProviderBackend from "./backend/ProviderBackend";
import * as Provider from "./auth/Provider";
import i18next from "i18next";
import BaseListPage from "./BaseListPage";
import PopconfirmModal from "./common/modal/PopconfirmModal";

class ProviderListPage extends BaseListPage {
  constructor(props) {
    super(props);
  }

  componentDidMount() {
    super.componentDidMount();
    this.setState({
      owner: Setting.isAdminUser(this.props.account) ? "admin" : this.props.account.owner,
    });
  }

  newProvider() {
    const randomName = Setting.getRandomName();
    const owner = Setting.isDefaultOrganizationSelected(this.props.account) ? this.state.owner : Setting.getRequestOrganization(this.props.account);
    return {
      owner: owner,
      name: `provider_${randomName}`,
      createdTime: moment().format(),
      displayName: `New Provider - ${randomName}`,
      category: "OAuth",
      type: "GitHub",
      method: "Normal",
      clientId: "",
      clientSecret: "",
      enableSignUp: true,
      host: "",
      port: 0,
      providerUrl: "https://github.com/organizations/xxx/settings/applications/1234567",
    };
  }

  addProvider() {
    const newProvider = this.newProvider();
    ProviderBackend.addProvider(newProvider)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/providers/${newProvider.owner}/${newProvider.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteProvider(i) {
    ProviderBackend.deleteProvider(this.state.data[i])
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

  renderTable(providers) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">{i18next.t("application:Providers")}</h1>
          <button
            id="add-button"
            className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100"
            onClick={this.addProvider.bind(this)}
          >
            {i18next.t("general:Add")}
          </button>
        </div>

        <div className="overflow-x-auto border border-white/10 rounded-xl">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Organization")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Created time")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Display name")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Category")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Type")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("provider:Client ID")}</th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {providers && providers.map((record, index) => (
                <tr key={`${record.owner}/${record.name}`} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <Link to={`/providers/${record.owner}/${record.name}`} className="text-white hover:underline">
                      {record.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-white">
                    {(record.owner !== "admin") ? record.owner : i18next.t("provider:admin (Shared)")}
                  </td>
                  <td className="px-4 py-3 text-gray-400">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-white">{record.displayName}</td>
                  <td className="px-4 py-3 text-white">{record.category}</td>
                  <td className="px-4 py-3">
                    {Provider.getProviderLogoWidget(record)}
                  </td>
                  <td className="px-4 py-3 text-gray-400">{Setting.getShortText(record.clientId)}</td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex justify-end gap-2">
                      <button
                        disabled={!Setting.isAdminUser(this.props.account) && (record.owner !== this.props.account.owner)}
                        className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1 disabled:opacity-50 disabled:cursor-not-allowed"
                        onClick={() => this.props.history.push(`/providers/${record.owner}/${record.name}`)}
                      >
                        <Pencil size={12} />
                        {i18next.t("general:Edit")}
                      </button>
                      <PopconfirmModal
                        title={i18next.t("general:Sure to delete") + `: ${record.name} ?`}
                        onConfirm={() => this.deleteProvider(index)}
                        disabled={!Setting.isAdminUser(this.props.account) && (record.owner !== this.props.account.owner)}
                      />
                    </div>
                  </td>
                </tr>
              ))}
              {(!providers || providers.length === 0) && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                    {this.state.loading ? i18next.t("general:Loading...") : i18next.t("general:No data")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>{i18next.t("general:{total} in total").replace("{total}", this.state.pagination.total)}</span>
          <div className="flex items-center gap-2">
            <button
              disabled={this.state.pagination.current <= 1}
              className="px-3 py-1 border border-white/10 rounded text-white disabled:opacity-30 disabled:cursor-not-allowed hover:bg-white/[0.05]"
              onClick={() => this.handleTableChange({...this.state.pagination, current: this.state.pagination.current - 1}, {}, {})}
            >
              Prev
            </button>
            <span className="text-white">{this.state.pagination.current}</span>
            <button
              disabled={this.state.pagination.current * this.state.pagination.pageSize >= this.state.pagination.total}
              className="px-3 py-1 border border-white/10 rounded text-white disabled:opacity-30 disabled:cursor-not-allowed hover:bg-white/[0.05]"
              onClick={() => this.handleTableChange({...this.state.pagination, current: this.state.pagination.current + 1}, {}, {})}
            >
              Next
            </button>
          </div>
        </div>
      </div>
    );
  }

  fetch = (params = {}) => {
    let field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (params.category !== undefined && params.category !== null) {
      field = "category";
      value = params.category;
    } else if (params.type !== undefined && params.type !== null) {
      field = "type";
      value = params.type;
    }
    this.setState({loading: true});
    (Setting.isDefaultOrganizationSelected(this.props.account) ? ProviderBackend.getGlobalProviders(params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
      : ProviderBackend.getProviders(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder))
      .then((res) => {
        this.setState({loading: false});
        if (res.status === "ok") {
          this.setState({
            data: res.data,
            pagination: {...params.pagination, total: res.data2},
            searchText: params.searchText,
            searchedColumn: params.searchedColumn,
          });
        } else {
          if (Setting.isResponseDenied(res)) {
            this.setState({isAuthorized: false});
          } else {
            Setting.showMessage("error", res.msg);
          }
        }
      });
  };
}

export default ProviderListPage;

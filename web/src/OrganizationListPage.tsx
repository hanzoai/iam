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
import {Pencil, Users, FolderTree} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import i18next from "i18next";
import BaseListPage from "./BaseListPage";
import PopconfirmModal from "./common/modal/PopconfirmModal";

class OrganizationListPage extends BaseListPage {
  newOrganization() {
    const randomName = Setting.getRandomName();
    const DefaultMfaRememberInHours = 12;
    return {
      owner: "admin",
      name: `organization_${randomName}`,
      createdTime: moment().format(),
      displayName: `New Organization - ${randomName}`,
      websiteUrl: "https://door.iam.com",
      favicon: `${Setting.StaticBaseUrl}/img/favicon.png`,
      passwordType: "bcrypt",
      PasswordSalt: "",
      passwordOptions: ["AtLeast6"],
      passwordObfuscatorType: "Plain",
      passwordObfuscatorKey: "",
      passwordExpireDays: 0,
      countryCodes: ["US"],
      defaultAvatar: `${Setting.StaticBaseUrl}/img/hanzo.svg`,
      defaultApplication: "",
      tags: [],
      languages: Setting.Countries.map(item => item.key),
      masterPassword: "",
      defaultPassword: "",
      enableSoftDeletion: false,
      isProfilePublic: true,
      enableTour: true,
      disableSignin: false,
      mfaRememberInHours: DefaultMfaRememberInHours,
      balanceCurrency: "USD",
      accountItems: [
        {name: "Organization", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "ID", visible: true, viewRule: "Public", modifyRule: "Immutable"},
        {name: "Name", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Display name", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "First name", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Last name", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Avatar", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "User type", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Password", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "Email", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Phone", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Country code", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Country/Region", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Location", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Address", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Addresses", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Affiliation", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Title", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "ID card type", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "ID card", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "ID card info", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Real name", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "ID verification", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "Homepage", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Bio", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Tag", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Language", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Gender", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Birthday", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Education", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Score", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Karma", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Ranking", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Balance", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Balance credit", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Balance currency", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Cart", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "Transactions", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "Signup application", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Register type", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Register source", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "API key", label: i18next.t("general:API key"), modifyRule: "Self"},
        {name: "Groups", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Roles", visible: true, viewRule: "Public", modifyRule: "Immutable"},
        {name: "Permissions", visible: true, viewRule: "Public", modifyRule: "Immutable"},
        {name: "Consents", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "3rd-party logins", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "Properties", visible: false, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Is online", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Is admin", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Is forbidden", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Is deleted", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Multi-factor authentication", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "MFA items", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "WebAuthn credentials", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "Last change password time", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Managed accounts", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "Face ID", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "MFA accounts", visible: true, viewRule: "Self", modifyRule: "Self"},
        {name: "Need update password", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "IP whitelist", visible: true, viewRule: "Admin", modifyRule: "Admin"},
      ],
    };
  }

  addOrganization() {
    const newOrganization = this.newOrganization();
    OrganizationBackend.addOrganization(newOrganization)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/organizations/${newOrganization.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
          window.dispatchEvent(new Event("storageOrganizationsChanged"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteOrganization(i) {
    OrganizationBackend.deleteOrganization(this.state.data[i])
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          this.fetch({
            pagination: {
              ...this.state.pagination,
              current: this.state.pagination.current > 1 && this.state.data.length === 1 ? this.state.pagination.current - 1 : this.state.pagination.current,
            },
          });
          window.dispatchEvent(new Event("storageOrganizationsChanged"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  renderTable(organizations) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">{i18next.t("general:Organizations")}</h1>
          <button
            className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
            disabled={!Setting.isAdminUser(this.props.account)}
            onClick={this.addOrganization.bind(this)}
          >
            {i18next.t("general:Add")}
          </button>
        </div>

        <div className="overflow-x-auto border border-white/10 rounded-xl">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Created time")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Display name")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Favicon")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("organization:Website URL")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Password type")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("organization:Soft deletion")}</th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {organizations && organizations.map((record, index) => (
                <tr key={record.name} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <Link to={`/organizations/${record.name}`} className="text-white hover:underline">
                      {record.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-white">{record.displayName}</td>
                  <td className="px-4 py-3">
                    {record.favicon && (
                      <a target="_blank" rel="noreferrer" href={record.favicon}>
                        <img src={record.favicon} alt="" className="w-8 h-8" />
                      </a>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <a target="_blank" rel="noreferrer" href={record.websiteUrl} className="text-gray-400 hover:text-white">
                      {record.websiteUrl}
                    </a>
                  </td>
                  <td className="px-4 py-3 text-white">{record.passwordType}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${record.enableSoftDeletion ? "bg-white/10 text-white" : "bg-white/5 text-gray-500"}`}>
                      {record.enableSoftDeletion ? i18next.t("general:ON") : i18next.t("general:OFF")}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex justify-end gap-2">
                      <button
                        className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1"
                        onClick={() => this.props.history.push(`/trees/${record.name}`)}
                      >
                        <FolderTree size={12} />
                        {i18next.t("general:Groups")}
                      </button>
                      <button
                        className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1"
                        onClick={() => this.props.history.push(`/organizations/${record.name}/users`)}
                      >
                        <Users size={12} />
                        {i18next.t("general:Users")}
                      </button>
                      <button
                        className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1"
                        onClick={() => this.props.history.push(`/organizations/${record.name}`)}
                      >
                        <Pencil size={12} />
                        {i18next.t("general:Edit")}
                      </button>
                      <PopconfirmModal
                        title={i18next.t("general:Sure to delete") + `: ${record.name} ?`}
                        onConfirm={() => this.deleteOrganization(index)}
                        disabled={record.name === "built-in"}
                      />
                    </div>
                  </td>
                </tr>
              ))}
              {(!organizations || organizations.length === 0) && (
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
    if (params.passwordType !== undefined && params.passwordType !== null) {
      field = "passwordType";
      value = params.passwordType;
    }
    this.setState({loading: true});
    OrganizationBackend.getOrganizations("admin", Setting.isDefaultOrganizationSelected(this.props.account) ? "" : Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
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
          if (Setting.isResponseDenied(res)) {
            this.setState({isAuthorized: false});
          } else {
            Setting.showMessage("error", res.msg);
          }
        }
      });
  };
}

export default OrganizationListPage;

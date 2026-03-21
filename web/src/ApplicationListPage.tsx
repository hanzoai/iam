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
import {Pencil, Copy} from "lucide-react";
import moment from "moment";
import * as Setting from "./Setting";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import i18next from "i18next";
import BaseListPage from "./BaseListPage";
import PopconfirmModal from "./common/modal/PopconfirmModal";
import {SignupTableDefaultCssMap} from "./table/SignupTable";

class ApplicationListPage extends BaseListPage {
  constructor(props) {
    super(props);
  }

  newApplication() {
    const randomName = Setting.getRandomName();
    const organizationName = Setting.getRequestOrganization(this.props.account);
    return {
      owner: "admin",
      name: `application_${randomName}`,
      organization: organizationName,
      createdTime: moment().format(),
      displayName: `New Application - ${randomName}`,
      category: "Default",
      type: "All",
      scopes: [],
      logo: `${Setting.StaticBaseUrl}/img/iam-logo_1185x256.png`,
      enablePassword: true,
      enableSignUp: true,
      disableSignin: false,
      enableSigninSession: false,
      enableCodeSignin: false,
      enableSamlCompress: false,
      disableSamlAttributes: false,
      providers: [
        {name: "provider_captcha_default", canSignUp: false, canSignIn: false, canUnlink: false, prompted: false, signupGroup: "", rule: ""},
      ],
      SigninMethods: [
        {name: "Password", displayName: "Password", rule: "All"},
        {name: "Verification code", displayName: "Verification code", rule: "All"},
        {name: "WebAuthn", displayName: "WebAuthn", rule: "None"},
        {name: "Face ID", displayName: "Face ID", rule: "None"},
      ],
      signupItems: [
        {name: "ID", visible: false, required: true, rule: "Random"},
        {name: "Username", visible: true, required: true, rule: "None"},
        {name: "Display name", visible: true, required: true, rule: "None"},
        {name: "Password", visible: true, required: true, rule: "None"},
        {name: "Confirm password", visible: true, required: true, rule: "None"},
        {name: "Email", visible: true, required: true, rule: "Normal"},
        {name: "Phone", visible: true, required: true, rule: "None"},
        {name: "Agreement", visible: true, required: true, rule: "None"},
        {name: "Signup button", visible: true, required: true, rule: "None"},
        {name: "Providers", visible: true, required: true, rule: "None", customCss: SignupTableDefaultCssMap["Providers"]},
      ],
      grantTypes: ["authorization_code", "password", "client_credentials", "token", "id_token", "refresh_token"],
      cert: "cert-hanzo",
      redirectUris: ["http://localhost:9000/callback"],
      tokenFormat: "JWT",
      tokenFields: [],
      expireInHours: 24 * 7,
      refreshExpireInHours: 24 * 7,
      cookieExpireInHours: 24 * 30,
      formOffset: 2,
    };
  }

  addApplication() {
    const newApplication = this.newApplication();
    ApplicationBackend.addApplication(newApplication)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/applications/${newApplication.organization}/${newApplication.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteApplication(i) {
    ApplicationBackend.deleteApplication(this.state.data[i])
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

  copyApplication(i) {
    const original = this.state.data[i];
    const randomSuffix = Setting.getRandomName();
    const newName = `${original.name}_${randomSuffix}`;

    const copiedApplication = {
      ...original,
      name: newName,
      createdTime: moment().format(),
      displayName: "Copy Application - " + newName,
      clientId: "",
      clientSecret: "",
    };

    ApplicationBackend.addApplication(copiedApplication)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/applications/${copiedApplication.organization}/${newName}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully copied"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to copy")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  renderTable(applications) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">{i18next.t("general:Applications")}</h1>
          <button
            className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100"
            onClick={this.addApplication.bind(this)}
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
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Category")}</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">Logo</th>
                <th className="px-4 py-3 text-left text-gray-400 font-medium">{i18next.t("general:Organization")}</th>
                <th className="px-4 py-3 text-right text-gray-400 font-medium">{i18next.t("general:Action")}</th>
              </tr>
            </thead>
            <tbody>
              {applications && applications.map((record, index) => (
                <tr key={`${record.owner}/${record.name}`} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <Link to={`/applications/${record.organization}/${record.name}`} className="text-white hover:underline">
                      {Setting.getApplicationDisplayName(record)}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{Setting.getFormattedDate(record.createdTime)}</td>
                  <td className="px-4 py-3 text-white">{record.displayName}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${record.category === "Agent" ? "bg-green-500/20 text-green-400" : "bg-white/10 text-gray-300"}`}>
                      {record.category || "Default"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {record.logo && (
                      <a target="_blank" rel="noreferrer" href={record.logo}>
                        <img src={record.logo} alt="" className="h-8 max-w-[120px] object-contain" />
                      </a>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/organizations/${record.organization}`} className="text-white hover:underline">
                      {record.organization}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex justify-end gap-2">
                      <button
                        className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1"
                        onClick={() => this.props.history.push(`/applications/${record.organization}/${record.name}`)}
                      >
                        <Pencil size={12} />
                        {i18next.t("general:Edit")}
                      </button>
                      <button
                        className="px-3 py-1.5 bg-white/[0.05] border border-white/10 rounded-lg text-xs text-white hover:bg-white/[0.08] inline-flex items-center gap-1"
                        onClick={() => this.copyApplication(index)}
                      >
                        <Copy size={12} />
                        {i18next.t("general:Copy")}
                      </button>
                      <PopconfirmModal
                        title={i18next.t("general:Sure to delete") + `: ${record.name} ?`}
                        onConfirm={() => this.deleteApplication(index)}
                        disabled={record.name === "app-hanzo"}
                      />
                    </div>
                  </td>
                </tr>
              ))}
              {(!applications || applications.length === 0) && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
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
    const field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    this.setState({loading: true});
    (Setting.isDefaultOrganizationSelected(this.props.account) ? ApplicationBackend.getApplications("admin", params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder) :
      ApplicationBackend.getApplicationsByOrganization("admin", Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder))
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

export default ApplicationListPage;

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
import {Copy, Link as LinkIcon, Upload as UploadIcon, Users, GripVertical} from "lucide-react";
import {Popover, PopoverContent, PopoverTrigger} from "./components/ui/popover";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import * as CertBackend from "./backend/CertBackend";
import * as Setting from "./Setting";
import * as Conf from "./Conf";
import * as ProviderBackend from "./backend/ProviderBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as ResourceBackend from "./backend/ResourceBackend";
import SignupPage from "./auth/SignupPage";
import LoginPage from "./auth/LoginPage";
import i18next from "i18next";
import UrlTable from "./table/UrlTable";
import ProviderTable from "./table/ProviderTable";
import SigninMethodTable from "./table/SigninMethodTable";
import SignupTable from "./table/SignupTable";
import SamlAttributeTable from "./table/SamlAttributeTable";
import ScopeTable from "./table/ScopeTable";
import PromptPage from "./auth/PromptPage";
import copy from "copy-to-clipboard";
import ThemeEditor from "./common/theme/ThemeEditor";

import SigninTable from "./table/SigninTable";
import Editor from "./common/Editor";
import * as GroupBackend from "./backend/GroupBackend";
import TokenAttributeTable from "./table/TokenAttributeTable";
import PaginateSelect from "./common/PaginateSelect";

const NATIVE_INPUT_CLASS = "w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white";
const NATIVE_SELECT_CLASS = "w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white";

const Switch = ({checked, disabled, onChange}) => (
  <button
    type="button"
    role="switch"
    aria-checked={!!checked}
    disabled={disabled}
    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${checked ? "bg-white" : "bg-white/20"} ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
    onClick={() => !disabled && onChange(!checked)}
  >
    <span className={`inline-block h-4 w-4 rounded-full transition-transform ${checked ? "translate-x-6 bg-black" : "translate-x-1 bg-gray-400"}`} />
  </button>
);

const RadioButtonGroup = ({value, onChange, options}) => (
  <div className="inline-flex rounded-lg overflow-hidden border border-white/10">
    {options.map((opt, i) => {
      const active = opt.value === value;
      return (
        <button
          key={i}
          type="button"
          className={`px-4 py-2 text-sm transition-colors ${active ? "bg-white text-black" : "bg-white/[0.02] text-white hover:bg-white/[0.05]"} ${i > 0 ? "border-l border-white/10" : ""}`}
          onClick={() => onChange(opt.value)}
        >
          {opt.label}
        </button>
      );
    })}
  </div>
);

const template = `<style>
  .login-panel {
    padding: 40px 70px 0 70px;
    border-radius: 10px;
    background-color: #ffffff;
    box-shadow: 0 0 30px 20px rgba(0, 0, 0, 0.20);
  }
  .login-panel-dark {
    padding: 40px 70px 0 70px;
    border-radius: 10px;
    background-color: #333333;
    box-shadow: 0 0 30px 20px rgba(255, 255, 255, 0.20);
  }
  .forget-content {
    padding: 10px 100px 20px;
    margin: 30px auto;
    border: 2px solid #fff;
    border-radius: 7px;
    background-color: rgb(255 255 255);
    box-shadow: 0 0 20px rgb(0 0 0 / 20%);
  }
</style>`;

const previewWidth = Setting.isMobile() ? "110%" : "90%";

const sideTemplate = `<style>
  .left-model{
    text-align: center;
    padding: 30px;
    background-color: #8ca0ed;
    position: absolute;
    transform: none;
    width: 100%;
    height: 100%;
  }
  .side-logo{
    display: flex;
    align-items: center;
  }
  .side-logo span {
    font-family: Montserrat, sans-serif;
    font-weight: 900;
    font-size: 2.4rem;
    line-height: 1.3;
    margin-left: 16px;
    color: #404040;
  }
  .img{
    max-width: none;
    margin: 41px 0 13px;
  }
</style>
<div class="left-model">
  <span class="side-logo"> <img src="${Setting.StaticBaseUrl}/img/iam-logo_1185x256.png" alt="IAM" style="width: 120px">
    <span>SSO</span>
  </span>
  <div class="img">
    <img src="${Setting.StaticBaseUrl}/img/hanzo.svg" alt="IAM"/>
  </div>
</div>
`;

class ApplicationEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      owner: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      applicationName: props.match.params.applicationName,
      application: null,
      organizations: [],
      certs: [],
      providers: [],
      uploading: false,
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
      tokenAttributes: [],
      samlAttributes: [],
      samlMetadata: null,
      isAuthorized: true,
      activeMenuKey: window.location.hash?.slice(1) || "basic",
      menuMode: "horizontal",
    };
  }

  UNSAFE_componentWillMount() {
    this.getApplication();
    this.getOrganizations();
  }

  getApplication() {
    ApplicationBackend.getApplication("admin", this.state.applicationName)
      .then((res) => {
        if (res.data === null) {
          this.props.history.push("/404");
          return;
        }

        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }

        const application = res.data;
        if (application.grantTypes === null || application.grantTypes === undefined || application.grantTypes.length === 0) {
          application.grantTypes = ["authorization_code"];
        }

        if (application.tags === null || application.tags === undefined) {
          application.tags = [];
        }

        this.setState({
          application: application,
        });

        this.getProviders(application);

        this.getCerts(application);

        this.getSamlMetadata(application.enableSamlPostBinding);
      });
  }

  getOrganizations() {
    OrganizationBackend.getOrganizations("admin")
      .then((res) => {
        if (res.status === "error") {
          this.setState({
            isAuthorized: false,
          });
        } else {
          this.setState({
            organizations: res.data || [],
          });
        }
      });
  }

  getCerts(application) {
    let owner = application.organization;
    if (application.isShared) {
      owner = this.props.owner;
    }
    CertBackend.getCerts(owner)
      .then((res) => {
        this.setState({
          certs: res.data || [],
        });
      });
  }

  getProviders(application) {
    let owner = application.organization;
    if (application.isShared) {
      owner = this.props.account.owner;
    }
    ProviderBackend.getProviders(owner)
      .then((res) => {
        if (res.status === "ok") {
          this.setState({
            providers: res.data,
          });
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
  }

  getSamlMetadata(checked) {
    ApplicationBackend.getSamlMetadata("admin", this.state.applicationName, checked)
      .then((data) => {
        this.setState({
          samlMetadata: data,
        });
      });
  }

  parseApplicationField(key, value) {
    if (["offset"].includes(key)) {
      value = Setting.myParseInt(value);
    }
    return value;
  }

  trimCustomScopes(customScopes) {
    if (!Array.isArray(customScopes)) {
      return [];
    }
    return customScopes.map((item) => {
      const scope = (item?.scope || "").trim();
      const displayName = (item?.displayName || "").trim();
      const description = (item?.description || "").trim();
      return {
        ...item,
        scope: scope,
        displayName: displayName,
        description: description,
      };
    });
  }

  validateCustomScopes(customScopes) {
    const trimmed = this.trimCustomScopes(customScopes);
    for (const item of trimmed) {
      if (!item || !item.scope || item.scope === "") {
        return {ok: false, scopes: trimmed};
      }
    }
    return {ok: true, scopes: trimmed};
  }

  updateApplicationField(key, value) {
    value = this.parseApplicationField(key, value);
    const application = this.state.application;
    application[key] = value;
    this.setState({
      application: application,
    });
  }

  handleUpload(file) {
    if (file.type !== "text/html") {
      Setting.showMessage("error", i18next.t("application:Please select a HTML file"));
      return;
    }
    this.setState({uploading: true});
    const fullFilePath = `termsOfUse/${this.state.application.owner}/${this.state.application.name}.html`;
    ResourceBackend.uploadResource(this.props.account.owner, this.props.account.name, "termsOfUse", "ApplicationEditPage", fullFilePath, file)
      .then(res => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("application:File uploaded successfully"));
          this.updateApplicationField("termsOfUse", res.data);
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
        }
      }).finally(() => {
        this.setState({uploading: false});
      });
  }

  renderRow(labelText, tooltipText, content, opts = {}) {
    const {labelSpan = 3, contentSpan = 21} = opts;
    return (
      <div className="grid grid-cols-12 gap-4 items-start mt-5">
        <div className={`col-span-12 md:col-span-${labelSpan} pt-2 text-sm text-gray-300`}>
          {tooltipText ? Setting.getLabel(labelText, tooltipText) : labelText} :
        </div>
        <div className={`col-span-12 md:col-span-${contentSpan}`}>
          {content}
        </div>
      </div>
    );
  }

  renderApplicationForm() {
    return <>
      {this.state.activeMenuKey === "basic" && (
        <React.Fragment>
          <div className="grid grid-cols-12 gap-4 items-start mt-2">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Name"), i18next.t("general:Name - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={this.state.application.name} disabled={this.state.application.name === "app-hanzo"}
                placeholder={`${this.state.application.organization?.toLowerCase() || "org"}-appname`}
                onChange={e => {
                  const value = e.target.value;
                  if (/[/?:@#&%=+;]/.test(value)) {
                    const invalidChars = "/ ? : @ # & % = + ;";
                    const messageText = i18next.t("application:Invalid characters in application name") + ":" + " " + invalidChars;
                    Setting.showMessage("error", messageText);
                    return;
                  }
                  const orgPrefix = (this.state.application.organization || "").toLowerCase() + "-";
                  if (value.length > 0 && !value.startsWith(orgPrefix) && !orgPrefix.startsWith(value)) {
                    Setting.showMessage("error", i18next.t("application:Application name must start with org prefix") + `: "${orgPrefix}"`);
                    return;
                  }
                  this.updateApplicationField("name", e.target.value);
                }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Display name"), i18next.t("general:Display name - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={this.state.application.displayName} onChange={e => {
                this.updateApplicationField("displayName", e.target.value);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Category"), i18next.t("general:Category - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} value={this.state.application.category} onChange={e => {
                const value = e.target.value;
                this.updateApplicationField("category", value);
                if (value === "Agent") {
                  this.updateApplicationField("type", "MCP");
                } else {
                  this.updateApplicationField("type", "All");
                }
              }}>
                <option value="Default">Default</option>
                <option value="Agent">Agent</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Type"), i18next.t("general:Type - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} value={this.state.application.type} onChange={e => {
                this.updateApplicationField("type", e.target.value);
              }}>
                {(this.state.application.category === "Agent") ? (
                  <>
                    <option value="MCP">MCP</option>
                    <option value="A2A">A2A</option>
                  </>
                ) : (
                  <>
                    <option value="All">All</option>
                    <option value="OIDC">OIDC</option>
                    <option value="OAuth">OAuth</option>
                    <option value="SAML">SAML</option>
                    <option value="CAS">CAS</option>
                  </>
                )}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Is shared"), i18next.t("general:Is shared - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <Switch disabled={Setting.isAdminUser()} checked={this.state.application.isShared} onChange={checked => {
                this.updateApplicationField("isShared", checked);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Logo"), i18next.t("general:Logo - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9 space-y-3">
              <div className="flex items-center gap-2">
                <LinkIcon size={14} className="text-gray-400" />
                <input className={"flex-1 " + NATIVE_INPUT_CLASS} value={this.state.application.logo} onChange={e => {
                  this.updateApplicationField("logo", e.target.value);
                }} />
              </div>
              {this.state.application.logo && (
                <a target="_blank" rel="noreferrer" href={this.state.application.logo}>
                  <img src={this.state.application.logo} alt={this.state.application.logo} height={90} style={{marginBottom: "20px"}} />
                </a>
              )}
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Title"), i18next.t("general:Title - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={this.state.application.title} onChange={e => {
                this.updateApplicationField("title", e.target.value);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Favicon"), i18next.t("general:Favicon - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9 space-y-3">
              <div className="flex items-center gap-2">
                <LinkIcon size={14} className="text-gray-400" />
                <input className={"flex-1 " + NATIVE_INPUT_CLASS} value={this.state.application.favicon} onChange={e => {
                  this.updateApplicationField("favicon", e.target.value);
                }} />
              </div>
              {this.state.application.favicon && (
                <a target="_blank" rel="noreferrer" href={this.state.application.favicon}>
                  <img src={this.state.application.favicon} alt={this.state.application.favicon} height={90} style={{marginBottom: "20px"}} />
                </a>
              )}
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Home"), i18next.t("general:Home - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <div className="flex items-center gap-2">
                <LinkIcon size={14} className="text-gray-400" />
                <input className={"flex-1 " + NATIVE_INPUT_CLASS} value={this.state.application.homepageUrl} onChange={e => {
                  this.updateApplicationField("homepageUrl", e.target.value);
                }} />
              </div>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Description"), i18next.t("general:Description - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={this.state.application.description} onChange={e => {
                this.updateApplicationField("description", e.target.value);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} disabled={!Setting.isAdminUser(this.props.account)} value={this.state.application.organization} onChange={e => {
                this.updateApplicationField("organization", e.target.value);
              }}>
                {this.state.organizations.map((organization, index) => <option key={index} value={organization.name}>{organization.name}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("organization:Tags"), i18next.t("application:Tags - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={(this.state.application.tags ?? []).join(",")}
                placeholder="comma-separated tags"
                onChange={e => {
                  const value = e.target.value;
                  const tags = value === "" ? [] : value.split(",").map(t => t.trim()).filter(t => t.length > 0);
                  this.updateApplicationField("tags", tags);
                }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Order"), i18next.t("application:Order - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input type="number" className={"w-[150px] " + NATIVE_INPUT_CLASS} value={this.state.application.order} min={0} step={1} onChange={e => {
                this.updateApplicationField("order", parseInt(e.target.value) || 0);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Menu mode"), i18next.t("application:Menu mode - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <RadioButtonGroup
                value={this.state.menuMode}
                onChange={(value) => this.setState({menuMode: value})}
                options={[
                  {value: "horizontal", label: i18next.t("application:Horizontal")},
                  {value: "vertical", label: i18next.t("application:Vertical")},
                ]}
              />
            </div>
          </div>
        </React.Fragment>
      )}

      {this.state.activeMenuKey === "authentication" && (
        <React.Fragment>
          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Cookie expire"), i18next.t("application:Cookie expire - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9 flex items-center gap-2">
              <input type="number" className={"w-[150px] " + NATIVE_INPUT_CLASS} value={this.state.application.cookieExpireInHours || 720} min={1} step={1} onChange={e => {
                this.updateApplicationField("cookieExpireInHours", parseInt(e.target.value) || 0);
              }} />
              <span className="text-sm text-gray-400">Hours</span>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("ldap:Default group"), i18next.t("ldap:Default group - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <PaginateSelect
                virtual
                style={{width: "100%"}}
                allowClear
                placeholder={i18next.t("general:Default")}
                value={this.state.application.defaultGroup || undefined}
                fetchPage={GroupBackend.getGroups}
                buildFetchArgs={({page, pageSize, searchText}) => {
                  const field = searchText ? "name" : "";
                  return [this.state.owner, false, page, pageSize, field, searchText, "", ""];
                }}
                reloadKey={this.state.owner}
                optionMapper={(group) => Setting.getOption(
                  <span className="flex items-center gap-2">
                    {group.type === "Physical" ? <Users size={14} /> : <GripVertical size={14} />}
                    {group.displayName}
                  </span>,
                  `${group.owner}/${group.name}`
                )}
                filterOption={false}
                onChange={(value) => {
                  this.updateApplicationField("defaultGroup", value || "");
                }}
              />
            </div>
          </div>

          {[
            {key: "enableSignUp", label: "application:Enable signup", tooltip: "application:Enable signup - Tooltip"},
            {key: "disableSignin", label: "application:Disable signin", tooltip: "application:Disable signin - Tooltip"},
            {key: "enableExclusiveSignin", label: "application:Enable exclusive signin", tooltip: "application:Enable exclusive signin - Tooltip"},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <Switch checked={this.state.application[item.key]} onChange={checked => {
                  this.updateApplicationField(item.key, checked);
                }} />
              </div>
            </div>
          ))}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Signin session"), i18next.t("application:Enable signin session - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <Switch checked={this.state.application.enableSigninSession} onChange={checked => {
                if (!checked) {
                  this.updateApplicationField("enableAutoSignin", false);
                }
                this.updateApplicationField("enableSigninSession", checked);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Auto signin"), i18next.t("application:Auto signin - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <Switch checked={this.state.application.enableAutoSignin} onChange={checked => {
                if (!this.state.application.enableSigninSession && checked) {
                  Setting.showMessage("error", i18next.t("application:Please enable \"Signin session\" first before enabling \"Auto signin\""));
                  return;
                }
                this.updateApplicationField("enableAutoSignin", checked);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Enable Email linking"), i18next.t("application:Enable Email linking - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <Switch checked={this.state.application.enableLinkWithEmail} onChange={checked => {
                this.updateApplicationField("enableLinkWithEmail", checked);
              }} />
            </div>
          </div>

          {[
            {key: "signupUrl", label: "general:Signup URL", tooltip: "general:Signup URL - Tooltip"},
            {key: "signinUrl", label: "general:Signin URL", tooltip: "general:Signin URL - Tooltip"},
            {key: "forgetUrl", label: "general:Forget URL", tooltip: "general:Forget URL - Tooltip"},
            {key: "affiliationUrl", label: "general:Affiliation URL", tooltip: "general:Affiliation URL - Tooltip"},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <div className="flex items-center gap-2">
                  <LinkIcon size={14} className="text-gray-400" />
                  <input className={"flex-1 " + NATIVE_INPUT_CLASS} value={this.state.application[item.key]} onChange={e => {
                    this.updateApplicationField(item.key, e.target.value);
                  }} />
                </div>
              </div>
            </div>
          ))}
        </React.Fragment>
      )}

      {this.state.activeMenuKey === "oidc-oauth" && (
        <React.Fragment>
          <div className="grid grid-cols-12 gap-4 items-start mt-2">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("provider:Client ID"), i18next.t("provider:Client ID - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={this.state.application.clientId} onChange={e => {
                this.updateApplicationField("clientId", e.target.value);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-2">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("provider:Client secret"), i18next.t("provider:Client secret - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={this.state.application.clientSecret} onChange={e => {
                this.updateApplicationField("clientSecret", e.target.value);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Redirect URLs"), i18next.t("application:Redirect URLs - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <UrlTable
                title={i18next.t("application:Redirect URLs")}
                table={this.state.application.redirectUris}
                onUpdateTable={(value) => {this.updateApplicationField("redirectUris", value);}}
              />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Forced redirect origin"), i18next.t("general:Forced redirect origin - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <div className="flex items-center gap-2">
                <LinkIcon size={14} className="text-gray-400" />
                <input className={"flex-1 " + NATIVE_INPUT_CLASS} value={this.state.application.forcedRedirectOrigin} onChange={e => {
                  this.updateApplicationField("forcedRedirectOrigin", e.target.value);
                }} />
              </div>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Grant types"), i18next.t("application:Grant types - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select multiple className={NATIVE_SELECT_CLASS + " h-40"} value={this.state.application.grantTypes ?? []} onChange={e => {
                this.updateApplicationField("grantTypes", Array.from(e.target.selectedOptions, o => o.value));
              }}>
                {[
                  {id: "authorization_code", name: "Authorization Code"},
                  {id: "password", name: "Password"},
                  {id: "client_credentials", name: "Client Credentials"},
                  {id: "token", name: "Token"},
                  {id: "id_token", name: "ID Token"},
                  {id: "refresh_token", name: "Refresh Token"},
                  {id: "urn:ietf:params:oauth:grant-type:device_code", name: "Device Code"},
                  {id: "urn:ietf:params:oauth:grant-type:jwt-bearer", name: "JWT Bearer"},
                ].map((item, index) => <option key={index} value={item.id}>{item.name}</option>)}
              </select>
            </div>
          </div>

          {this.state.application.category === "Agent" ? (
            <div className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t("general:Scopes"), i18next.t("general:Scopes - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <ScopeTable
                  title={i18next.t("general:Scopes")}
                  table={this.state.application.scopes}
                  onUpdateTable={(value) => {this.updateApplicationField("scopes", value);}}
                />
              </div>
            </div>
          ) : null}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Token format"), i18next.t("application:Token format - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} value={this.state.application.tokenFormat} onChange={e => {
                this.updateApplicationField("tokenFormat", e.target.value);
              }}>
                {["JWT", "JWT-Empty", "JWT-Custom", "JWT-Standard"].map(item => <option key={item} value={item}>{item}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Token signing method"), i18next.t("application:Token signing method - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} value={this.state.application.tokenSigningMethod === "" ? "RS256" : this.state.application.tokenSigningMethod} onChange={e => {
                this.updateApplicationField("tokenSigningMethod", e.target.value);
              }}>
                {["RS256", "RS512", "ES256", "ES512", "ES384"].map(item => <option key={item} value={item}>{item}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Token fields"), i18next.t("application:Token fields - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select multiple disabled={this.state.application.tokenFormat !== "JWT-Custom"} className={NATIVE_SELECT_CLASS + " h-40"} value={this.state.application.tokenFields ?? []} onChange={e => {
                this.updateApplicationField("tokenFields", Array.from(e.target.selectedOptions, o => o.value));
              }}>
                <option key="signinMethod" value="signinMethod">SigninMethod</option>
                <option key="provider" value="provider">Provider</option>
                {[...Setting.getUserCommonFields(), "permissionNames"].map((item, index) => <option key={index} value={item}>{item}</option>)}
              </select>
            </div>
          </div>

          {this.state.application.tokenFormat === "JWT-Custom" ? (
            <div className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t("general:Token attributes"), i18next.t("general:Token attributes - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <TokenAttributeTable
                  title={i18next.t("general:Token attributes")}
                  table={this.state.application.tokenAttributes}
                  application={this.state.application}
                  onUpdateTable={(value) => {this.updateApplicationField("tokenAttributes", value);}}
                />
              </div>
            </div>
          ) : null}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Token expire"), i18next.t("application:Token expire - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9 flex items-center gap-2">
              <input type="number" className={"w-[150px] " + NATIVE_INPUT_CLASS} value={this.state.application.expireInHours} min={0.01} step={1} onChange={e => {
                this.updateApplicationField("expireInHours", parseFloat(e.target.value) || 0);
              }} />
              <span className="text-sm text-gray-400">Hours</span>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Refresh token expire"), i18next.t("application:Refresh token expire - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9 flex items-center gap-2">
              <input type="number" className={"w-[150px] " + NATIVE_INPUT_CLASS} value={this.state.application.refreshExpireInHours} min={0.01} step={1} onChange={e => {
                this.updateApplicationField("refreshExpireInHours", parseFloat(e.target.value) || 0);
              }} />
              <span className="text-sm text-gray-400">Hours</span>
            </div>
          </div>
        </React.Fragment>
      )}

      {this.state.activeMenuKey === "saml" && (
        <React.Fragment>
          <div className="grid grid-cols-12 gap-4 items-start mt-2">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:SAML reply URL"), i18next.t("application:Redirect URL (Assertion Consumer Service POST Binding URL) - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <div className="flex items-center gap-2">
                <LinkIcon size={14} className="text-gray-400" />
                <input className={"flex-1 " + NATIVE_INPUT_CLASS} value={this.state.application.samlReplyUrl} onChange={e => {
                  this.updateApplicationField("samlReplyUrl", e.target.value);
                }} />
              </div>
            </div>
          </div>

          {[
            {key: "enableSamlCompress", label: "application:Enable SAML compression", tooltip: "application:Enable SAML compression - Tooltip"},
            {key: "enableSamlC14n10", label: "application:Enable SAML C14N10", tooltip: "application:Enable SAML C14N10 - Tooltip"},
            {key: "useEmailAsSamlNameId", label: "application:Use Email as NameID", tooltip: "application:Use Email as NameID - Tooltip"},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <Switch checked={this.state.application[item.key]} onChange={checked => {
                  this.updateApplicationField(item.key, checked);
                }} />
              </div>
            </div>
          ))}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Enable SAML POST binding"), i18next.t("application:Enable SAML POST binding - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <Switch checked={this.state.application.enableSamlPostBinding} onChange={checked => {
                this.updateApplicationField("enableSamlPostBinding", checked);
                this.getSamlMetadata(checked);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:SAML hash algorithm"), i18next.t("application:SAML hash algorithm - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} value={this.state.application.samlHashAlgorithm} onChange={e => {
                this.updateApplicationField("samlHashAlgorithm", e.target.value);
              }}>
                {["SHA1", "SHA256", "SHA512"].map(item => <option key={item} value={item}>{item}</option>)}
              </select>
            </div>
          </div>

          {[
            {key: "disableSamlAttributes", label: "application:Disable SAML attributes", tooltip: "application:Disable SAML attributes - Tooltip"},
            {key: "enableSamlAssertionSignature", label: "application:Enable SAML assertion signature", tooltip: "application:Enable SAML assertion signature - Tooltip"},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <Switch checked={this.state.application[item.key]} onChange={checked => {
                  this.updateApplicationField(item.key, checked);
                }} />
              </div>
            </div>
          ))}

          {!this.state.application.disableSamlAttributes ? (
            <div className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t("general:SAML attributes"), i18next.t("general:SAML attributes - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <SamlAttributeTable
                  title={i18next.t("general:SAML attributes")}
                  table={this.state.application.samlAttributes}
                  application={this.state.application}
                  onUpdateTable={(value) => {this.updateApplicationField("samlAttributes", value);}}
                />
              </div>
            </div>
          ) : null}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:SAML metadata"), i18next.t("application:SAML metadata - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <Editor value={this.state.samlMetadata?.toString() ?? ""} lang="xml" readOnly />
              <br />
              <button
                className="px-4 py-2 bg-white text-black rounded-full text-sm font-medium hover:bg-gray-100 inline-flex items-center gap-2 mb-2"
                onClick={() => {
                  copy(`${window.location.origin}/v1/iam/saml/metadata?application=admin/${encodeURIComponent(this.state.applicationName)}&enablePostBinding=${this.state.application.enableSamlPostBinding}`);
                  Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully"));
                }}
              >
                <Copy size={14} />
                {i18next.t("application:Copy SAML metadata URL")}
              </button>
            </div>
          </div>
        </React.Fragment>
      )}

      {this.state.activeMenuKey === "providers" && (
        <React.Fragment>
          <div className="grid grid-cols-12 gap-4 items-start mt-2">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Providers"), i18next.t("general:Providers - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <ProviderTable
                title={i18next.t("application:Providers")}
                table={this.state.application.providers}
                providers={this.state.providers}
                application={this.state.application}
                onUpdateTable={(value) => {this.updateApplicationField("providers", value);}}
              />
            </div>
          </div>
        </React.Fragment>
      )}

      {this.state.activeMenuKey === "ui-customization" && (
        <React.Fragment>
          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Org choice mode"), i18next.t("application:Org choice mode - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} value={this.state.application.orgChoiceMode ?? ""} onChange={e => {
                this.updateApplicationField("orgChoiceMode", e.target.value);
              }}>
                <option value="None">{i18next.t("general:None")}</option>
                <option value="Select">{i18next.t("application:Select")}</option>
                <option value="Input">{i18next.t("application:Input")}</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Signin methods"), i18next.t("application:Signin methods - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <SigninMethodTable
                title={i18next.t("application:Signin methods")}
                table={this.state.application.signinMethods}
                onUpdateTable={(value) => {
                  this.updateApplicationField("signinMethods", value);
                }}
              />
            </div>
          </div>

          {[
            {key: "signupHtml", label: "provider:Signup HTML", tooltip: "provider:Signup HTML - Tooltip", editLabel: "provider:Signup HTML - Edit"},
            {key: "signinHtml", label: "provider:Signin HTML", tooltip: "provider:Signin HTML - Tooltip", editLabel: "provider:Signin HTML - Edit"},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <Popover>
                  <PopoverTrigger asChild>
                    <input className={NATIVE_INPUT_CLASS + " mb-2"} value={this.state.application[item.key]} onChange={e => {
                      this.updateApplicationField(item.key, e.target.value);
                    }} />
                  </PopoverTrigger>
                  <PopoverContent side="right" className="w-[900px]">
                    <div className="text-sm font-medium mb-2">{i18next.t(item.editLabel)}</div>
                    <div style={{width: "100%", height: "300px"}}>
                      <Editor value={this.state.application[item.key]} lang="html" fillHeight dark onChange={value => {
                        this.updateApplicationField(item.key, value);
                      }} />
                    </div>
                  </PopoverContent>
                </Popover>
              </div>
            </div>
          ))}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Signin items"), i18next.t("application:Signin items - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <SigninTable
                title={i18next.t("application:Signin items")}
                table={this.state.application.signinItems}
                themeAlgorithm={this.state.themeAlgorithm}
                onUpdateTable={(value) => {
                  this.updateApplicationField("signinItems", value);
                }}
              />
            </div>
          </div>

          {!this.state.application.enableSignUp ? null : (
            <div className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t("application:Signup items"), i18next.t("application:Signup items - Tooltip"))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <SignupTable
                  title={i18next.t("application:Signup items")}
                  table={this.state.application.signupItems}
                  onUpdateTable={(value) => {
                    this.updateApplicationField("signupItems", value);
                  }}
                />
              </div>
            </div>
          )}

          <div className="grid grid-cols-12 gap-4 items-start mt-2">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Preview"), i18next.t("general:Preview - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              {this.renderSignupSigninPreview()}
            </div>
          </div>

          {[
            {key: "formBackgroundUrl", label: "application:Background URL", tooltip: "application:Background URL - Tooltip"},
            {key: "formBackgroundUrlMobile", label: "application:Background URL Mobile", tooltip: "application:Background URL Mobile - Tooltip"},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9 space-y-3">
                <div className="flex items-center gap-2">
                  <LinkIcon size={14} className="text-gray-400" />
                  <input className={"flex-1 " + NATIVE_INPUT_CLASS} value={this.state.application[item.key]} onChange={e => {
                    this.updateApplicationField(item.key, e.target.value);
                  }} />
                </div>
                {this.state.application[item.key] && (
                  <a target="_blank" rel="noreferrer" href={this.state.application[item.key]}>
                    <img src={this.state.application[item.key]} alt={this.state.application[item.key]} height={90} style={{marginBottom: "20px"}} />
                  </a>
                )}
              </div>
            </div>
          ))}

          {[
            {key: "formCss", label: "application:Custom CSS", tooltip: "application:Custom CSS - Tooltip", editLabel: "application:Custom CSS - Edit", fallback: template},
            {key: "formCssMobile", label: "application:Custom CSS Mobile", tooltip: "application:Custom CSS Mobile - Tooltip", editLabel: "application:Custom CSS Mobile - Edit", fallback: template},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-2">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <Popover>
                  <PopoverTrigger asChild>
                    <input className={NATIVE_INPUT_CLASS + " mb-2"} value={this.state.application[item.key]} onChange={e => {
                      this.updateApplicationField(item.key, e.target.value);
                    }} />
                  </PopoverTrigger>
                  <PopoverContent side="right" className="w-[900px]">
                    <div className="text-sm font-medium mb-2">{i18next.t(item.editLabel)}</div>
                    <div style={{width: "100%", height: "300px"}}>
                      <Editor
                        value={this.state.application[item.key] === "" ? item.fallback : this.state.application[item.key]}
                        lang="css"
                        fillHeight
                        dark
                        onChange={value => {
                          this.updateApplicationField(item.key, value);
                        }}
                      />
                    </div>
                  </PopoverContent>
                </Popover>
              </div>
            </div>
          ))}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Form position"), i18next.t("application:Form position - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <RadioButtonGroup
                value={this.state.application.formOffset}
                onChange={(value) => this.updateApplicationField("formOffset", value)}
                options={[
                  {value: 1, label: i18next.t("application:Left")},
                  {value: 2, label: i18next.t("application:Center")},
                  {value: 3, label: i18next.t("application:Right")},
                  {value: 4, label: i18next.t("application:Enable side panel")},
                ]}
              />
              {this.state.application.formOffset === 4 ? (
                <div className="grid grid-cols-12 gap-4 items-start mt-5">
                  <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                    {Setting.getLabel(i18next.t("application:Side panel HTML"), i18next.t("application:Side panel HTML - Tooltip"))} :
                  </div>
                  <div className="col-span-12 md:col-span-9">
                    <Popover>
                      <PopoverTrigger asChild>
                        <input className={NATIVE_INPUT_CLASS + " mb-2"} value={this.state.application.formSideHtml} onChange={e => {
                          this.updateApplicationField("formSideHtml", e.target.value);
                        }} />
                      </PopoverTrigger>
                      <PopoverContent side="right" className="w-[900px]">
                        <div className="text-sm font-medium mb-2">{i18next.t("application:Side panel HTML - Edit")}</div>
                        <div style={{width: "100%", height: "300px"}}>
                          <Editor
                            value={this.state.application.formSideHtml === "" ? sideTemplate : this.state.application.formSideHtml}
                            lang="html"
                            fillHeight
                            dark
                            onChange={value => {
                              this.updateApplicationField("formSideHtml", value);
                            }}
                          />
                        </div>
                      </PopoverContent>
                    </Popover>
                  </div>
                </div>
              ) : null}
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("theme:Theme"), i18next.t("theme:Theme - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9 pt-1">
              <RadioButtonGroup
                value={this.state.application.themeData?.isEnabled ?? false}
                onChange={(value) => {
                  const {_, ...theme} = this.state.application.themeData ?? {...Conf.ThemeDefault, isEnabled: false};
                  this.updateApplicationField("themeData", {...theme, isEnabled: value});
                }}
                options={[
                  {value: false, label: i18next.t("application:Follow organization theme")},
                  {value: true, label: i18next.t("theme:Customize theme")},
                ]}
              />
              {this.state.application.themeData?.isEnabled ? (
                <div className="mt-5">
                  <ThemeEditor themeData={this.state.application.themeData} onThemeChange={(_, nextThemeData) => {
                    const {isEnabled} = this.state.application.themeData ?? {...Conf.ThemeDefault, isEnabled: false};
                    this.updateApplicationField("themeData", {...nextThemeData, isEnabled});
                  }} />
                </div>
              ) : null}
            </div>
          </div>

          {[
            {key: "headerHtml", label: "application:Header HTML", tooltip: "application:Header HTML - Tooltip", editLabel: "application:Header HTML - Edit"},
            {key: "footerHtml", label: "application:Footer HTML", tooltip: "application:Footer HTML - Tooltip", editLabel: "application:Footer HTML - Edit"},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <Popover>
                  <PopoverTrigger asChild>
                    <input className={NATIVE_INPUT_CLASS + " mb-2"} value={this.state.application[item.key]} onChange={e => {
                      this.updateApplicationField(item.key, e.target.value);
                    }} />
                  </PopoverTrigger>
                  <PopoverContent side="right" className="w-[900px]">
                    <div className="text-sm font-medium mb-2">{i18next.t(item.editLabel)}</div>
                    <div style={{width: "100%", height: "300px"}}>
                      <Editor
                        value={this.state.application[item.key]}
                        lang="html"
                        fillHeight
                        dark
                        onChange={value => {
                          this.updateApplicationField(item.key, value);
                        }}
                      />
                    </div>
                  </PopoverContent>
                </Popover>
              </div>
            </div>
          ))}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3" />
            <div className="col-span-12 md:col-span-9 flex flex-wrap gap-2">
              <button
                className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]"
                onClick={() => this.updateApplicationField("footerHtml", Setting.getDefaultFooterContent())}
              >
                {i18next.t("general:Reset to Default")}
              </button>
              <button
                className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]"
                onClick={() => this.updateApplicationField("footerHtml", Setting.getEmptyFooterContent())}
              >
                {i18next.t("application:Reset to Empty")}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:Preview"), i18next.t("general:Preview - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              {this.renderPromptPreview()}
            </div>
          </div>
        </React.Fragment>
      )}

      {this.state.activeMenuKey === "security" && (
        <React.Fragment>
          {[
            {key: "cert", label: "application:Token cert", tooltip: "application:Token cert - Tooltip"},
            {key: "clientCert", label: "application:Client cert", tooltip: "application:Client cert - Tooltip"},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9">
                <select className={NATIVE_SELECT_CLASS} value={this.state.application[item.key]} onChange={e => {
                  this.updateApplicationField(item.key, e.target.value);
                }}>
                  {this.state.certs.map((cert, index) => <option key={index} value={cert.name}>{cert.name}</option>)}
                </select>
              </div>
            </div>
          ))}

          {[
            {key: "failedSigninLimit", label: "application:Failed signin limit", tooltip: "application:Failed signin limit - Tooltip", suffix: "Times", min: 1},
            {key: "failedSigninFrozenTime", label: "application:Failed signin frozen time", tooltip: "application:Failed signin frozen time - Tooltip", suffix: "Minutes", min: 1},
            {key: "codeResendTimeout", label: "application:Code resend timeout", tooltip: "application:Code resend timeout - Tooltip", suffix: "Seconds", min: 0},
          ].map(item => (
            <div key={item.key} className="grid grid-cols-12 gap-4 items-start mt-5">
              <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
                {Setting.getLabel(i18next.t(item.label), i18next.t(item.tooltip))} :
              </div>
              <div className="col-span-12 md:col-span-9 flex items-center gap-2">
                <input type="number" className={"w-[150px] " + NATIVE_INPUT_CLASS} value={this.state.application[item.key]} min={item.min} step={1} onChange={e => {
                  this.updateApplicationField(item.key, parseInt(e.target.value) || 0);
                }} />
                <span className="text-sm text-gray-400">{item.suffix}</span>
              </div>
            </div>
          ))}

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("general:IP whitelist"), i18next.t("general:IP whitelist - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} placeholder={this.state.application.organizationObj?.ipWhitelist} value={this.state.application.ipWhitelist} onChange={e => {
                this.updateApplicationField("ipWhitelist", e.target.value);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("signup:Terms of Use"), i18next.t("signup:Terms of Use - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9 space-y-2">
              <div className="flex items-center gap-2">
                <LinkIcon size={14} className="text-gray-400" />
                <input className={"flex-1 " + NATIVE_INPUT_CLASS} value={this.state.application.termsOfUse} onChange={e => {
                  this.updateApplicationField("termsOfUse", e.target.value);
                }} />
              </div>
              <label className="inline-flex items-center gap-2 px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05] cursor-pointer">
                <UploadIcon size={14} />
                {this.state.uploading ? i18next.t("general:Uploading") + "..." : i18next.t("general:Click to Upload")}
                <input
                  type="file"
                  accept=".html"
                  className="hidden"
                  disabled={this.state.uploading}
                  onChange={e => {
                    const file = e.target.files?.[0];
                    if (file) {
                      this.handleUpload(file);
                    }
                    e.target.value = "";
                  }}
                />
              </label>
            </div>
          </div>
        </React.Fragment>
      )}

      {this.state.activeMenuKey === "reverse-proxy" && (
        <React.Fragment>
          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("provider:Domain"), i18next.t("provider:Domain - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={this.state.application.domain} placeholder="e.g., blog.example.com" onChange={e => {
                this.updateApplicationField("domain", e.target.value);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Other domains"), i18next.t("application:Other domains - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <UrlTable
                title={i18next.t("application:Other domains")}
                table={this.state.application.otherDomains}
                onUpdateTable={(value) => {this.updateApplicationField("otherDomains", value);}}
              />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:Upstream host"), i18next.t("application:Upstream host - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <input className={NATIVE_INPUT_CLASS} value={this.state.application.upstreamHost} placeholder="e.g., localhost:8080 or 192.168.1.100:3000" onChange={e => {
                this.updateApplicationField("upstreamHost", e.target.value);
              }} />
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("provider:SSL mode"), i18next.t("provider:SSL mode - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} value={this.state.application.sslMode} onChange={e => {
                this.updateApplicationField("sslMode", e.target.value);
              }}>
                <option value="">{i18next.t("general:None")}</option>
                <option value="HTTP">HTTP</option>
                <option value="HTTPS and HTTP">HTTPS and HTTP</option>
                <option value="HTTPS Only">HTTPS Only</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 items-start mt-5">
            <div className="col-span-12 md:col-span-3 pt-2 text-sm text-gray-300">
              {Setting.getLabel(i18next.t("application:SSL cert"), i18next.t("application:SSL cert - Tooltip"))} :
            </div>
            <div className="col-span-12 md:col-span-9">
              <select className={NATIVE_SELECT_CLASS} value={this.state.application.sslCert} onChange={e => {
                this.updateApplicationField("sslCert", e.target.value);
              }}>
                <option value="">{i18next.t("general:None")}</option>
                {this.state.certs.map((cert, index) => <option key={index} value={cert.name}>{cert.name}</option>)}
              </select>
            </div>
          </div>
        </React.Fragment>
      )}
    </>;
  }

  renderApplication() {
    const tabs = [
      {label: i18next.t("application:Basic"), key: "basic"},
      {label: i18next.t("application:Authentication"), key: "authentication"},
      {label: "OIDC/OAuth", key: "oidc-oauth"},
      {label: "SAML", key: "saml"},
      {label: i18next.t("application:Providers"), key: "providers"},
      {label: i18next.t("application:UI Customization"), key: "ui-customization"},
      {label: i18next.t("application:Security"), key: "security"},
      {label: i18next.t("application:Reverse Proxy"), key: "reverse-proxy"},
    ];

    const isHorizontal = this.state.menuMode === "horizontal" || !this.state.menuMode;

    return (
      <div className="bg-white/[0.02] border border-white/10 rounded-xl p-6" style={{height: "calc(100vh - 145px - 48px)", overflow: "hidden"}}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">
            {this.state.mode === "add" ? i18next.t("application:New Application") : i18next.t("application:Edit Application")}
          </h2>
          <div className="flex gap-2">
            <button className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.submitApplicationEdit(false)}>{i18next.t("general:Save")}</button>
            <button className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100" onClick={() => this.submitApplicationEdit(true)}>{i18next.t("general:Save & Exit")}</button>
            {this.state.mode === "add" && <button className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.deleteApplication()}>{i18next.t("general:Cancel")}</button>}
          </div>
        </div>

        <div className="flex flex-col h-full overflow-auto">
          {isHorizontal && (
            <div className="sticky top-0 z-10 bg-[#0a0a0a]/95 backdrop-blur border-b border-white/10 mb-4">
              <div className="flex flex-wrap gap-1">
                {tabs.map(tab => {
                  const active = this.state.activeMenuKey === tab.key;
                  return (
                    <button
                      key={tab.key}
                      type="button"
                      onClick={() => {
                        this.setState({activeMenuKey: tab.key});
                        window.location.hash = tab.key;
                      }}
                      className={`px-4 py-2 text-sm rounded-t-md transition-colors ${active ? "bg-white/[0.08] text-white border-t border-l border-r border-white/10" : "text-gray-400 hover:text-white"}`}
                    >
                      {tab.label}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <div className="flex gap-4 flex-1 overflow-auto">
            {!isHorizontal && (
              <div className="w-[200px] sticky top-0 self-start space-y-1">
                {tabs.map(tab => {
                  const active = this.state.activeMenuKey === tab.key;
                  return (
                    <button
                      key={tab.key}
                      type="button"
                      onClick={() => {
                        this.setState({activeMenuKey: tab.key});
                        window.location.hash = tab.key;
                      }}
                      className={`block w-full text-left px-3 py-2 text-sm rounded-md transition-colors ${active ? "bg-white/[0.08] text-white" : "text-gray-400 hover:bg-white/[0.05] hover:text-white"}`}
                    >
                      {tab.label}
                    </button>
                  );
                })}
              </div>
            )}

            <div className="flex-1 px-4 overflow-y-auto pb-20">
              {this.renderApplicationForm()}
            </div>
          </div>
        </div>
      </div>
    );
  }

  renderSignupSigninPreview() {
    const themeData = this.state.application.themeData ?? Conf.ThemeDefault;
    let signUpUrl = `/signup/${this.state.application.name}`;

    let redirectUri;
    if (this.state.application.redirectUris?.length > 0) {
      redirectUri = this.state.application.redirectUris[0];
    } else {
      redirectUri = "\"ERROR: You must specify at least one Redirect URL in 'Redirect URLs'\"";
    }

    let clientId = this.state.application.clientId;
    if (this.state.application.isShared) {
      clientId += `-org-${this.props.account.owner}`;
    }
    const signInUrl = `/login/oauth/authorize?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&scope=read&state=iam`;
    const maskStyle = {position: "absolute", top: "0px", left: "0px", zIndex: 10, height: "97%", width: "100%", background: "rgba(0,0,0,0.4)"};
    if (!Setting.isPasswordEnabled(this.state.application)) {
      signUpUrl = signInUrl.replace("/login/oauth/authorize", "/signup/oauth/authorize");
    }

    // Note: previously wrapped each preview in antd ConfigProvider to set theme tokens; with antd removed,
    // theme colors flow through Tailwind/CSS vars from globals.css. themeData remains in state so the
    // child SignupPage/LoginPage components can still consult it.
    void themeData;

    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <button
            className="px-4 py-2 bg-white text-black rounded-full text-sm font-medium hover:bg-gray-100 inline-flex items-center gap-2 mb-2"
            onClick={() => {
              copy(`${window.location.origin}${signUpUrl}`);
              Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully"));
            }}
          >
            <Copy size={14} />
            {i18next.t("application:Copy signup page URL")}
          </button>
          <br />
          <div style={{position: "relative", width: previewWidth, border: "1px solid rgb(217,217,217)", boxShadow: "10px 10px 5px #888888", overflow: "auto"}}>
            {Setting.isPasswordEnabled(this.state.application) ? (
              <div className="loginBackground" style={{backgroundImage: `url(${this.state.application?.formBackgroundUrl})`, overflow: "auto"}}>
                <SignupPage application={this.state.application} preview="auto" />
              </div>
            ) : (
              <div className="loginBackground" style={{backgroundImage: `url(${this.state.application?.formBackgroundUrl})`, overflow: "auto"}}>
                <LoginPage type={"login"} mode={"signup"} application={this.state.application} preview="auto" />
              </div>
            )}
            <div style={{overflow: "auto", ...maskStyle}} />
          </div>
        </div>
        <div>
          <button
            className="px-4 py-2 bg-white text-black rounded-full text-sm font-medium hover:bg-gray-100 inline-flex items-center gap-2 mb-2"
            style={{marginTop: Setting.isMobile() ? "15px" : "0"}}
            onClick={() => {
              copy(`${window.location.origin}${signInUrl}`);
              Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully"));
            }}
          >
            <Copy size={14} />
            {i18next.t("application:Copy signin page URL")}
          </button>
          <br />
          <div style={{position: "relative", width: previewWidth, border: "1px solid rgb(217,217,217)", boxShadow: "10px 10px 5px #888888", overflow: "auto"}}>
            <div className="loginBackground" style={{backgroundImage: `url(${this.state.application?.formBackgroundUrl})`, overflow: "auto"}}>
              <LoginPage type={"login"} mode={"signin"} application={this.state.application} preview="auto" />
            </div>
            <div style={{overflow: "auto", ...maskStyle}} />
          </div>
        </div>
      </div>
    );
  }

  renderPromptPreview() {
    const themeData = this.state.application.themeData ?? Conf.ThemeDefault;
    const promptUrl = `/prompt/${this.state.application.name}`;
    const maskStyle = {position: "absolute", top: "0px", left: "0px", zIndex: 10, height: "100%", width: "100%", background: "rgba(0,0,0,0.4)"};

    // ConfigProvider removed alongside antd; themeData kept in state so PromptPage can still consult it.
    void themeData;

    return (
      <div>
        <button
          className="px-4 py-2 bg-white text-black rounded-full text-sm font-medium hover:bg-gray-100 inline-flex items-center gap-2 mb-2"
          onClick={() => {
            copy(`${window.location.origin}${promptUrl}`);
            Setting.showMessage("success", i18next.t("general:Copied to clipboard successfully"));
          }}
        >
          <Copy size={14} />
          {i18next.t("application:Copy prompt page URL")}
        </button>
        <br />
        <div style={{position: "relative", width: previewWidth, border: "1px solid rgb(217,217,217)", boxShadow: "10px 10px 5px #888888", flexDirection: "column", flex: "auto"}}>
          <PromptPage application={this.state.application} account={this.props.account} />
          <div style={maskStyle} />
        </div>
      </div>
    );
  }

  submitApplicationEdit(exitAfterSave) {
    const application = Setting.deepCopy(this.state.application);
    application.providers = application.providers?.filter(provider => this.state.providers.map(provider => provider.name).includes(provider.name));
    application.signinMethods = application.signinMethods?.filter(signinMethod => ["Password", "Verification code", "WebAuthn", "LDAP", "Face ID", "WeChat"].includes(signinMethod.name));
    const customScopeValidation = this.validateCustomScopes(application.customScopes);
    application.customScopes = customScopeValidation.scopes;
    if (!customScopeValidation.ok) {
      Setting.showMessage("error", `${i18next.t("general:Name")}: ${i18next.t("provider:This field is required")}`);
      return;
    }

    const orgPrefix = (application.organization || "").toLowerCase() + "-";
    const appNamePattern = /^[a-z0-9]+-[a-z0-9]+(-[a-z0-9]+)*$/;
    if (!appNamePattern.test(application.name)) {
      Setting.showMessage("error", i18next.t("application:Application name must follow '<org>-<app>' format using lowercase alphanumeric segments"));
      return;
    }
    if (!application.name.startsWith(orgPrefix)) {
      Setting.showMessage("error", `${i18next.t("application:Application name must start with org prefix")}: "${orgPrefix}"`);
      return;
    }

    ApplicationBackend.updateApplication("admin", this.state.applicationName, application)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            applicationName: this.state.application.name,
          });

          if (exitAfterSave) {
            this.props.history.push("/applications");
          } else {
            this.props.history.push(`/applications/${this.state.application.organization}/${this.state.application.name}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updateApplicationField("name", this.state.applicationName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteApplication() {
    ApplicationBackend.deleteApplication(this.state.application)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push("/applications");
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  render() {
    if (!this.state.isAuthorized) {
      return (
        <div className="flex flex-col items-center justify-center py-20 space-y-4">
          <h1 className="text-4xl font-bold text-white">403 Unauthorized</h1>
          <p className="text-gray-400">{i18next.t("general:Sorry, you do not have permission to access this page or logged in status invalid.")}</p>
          <a href="/" className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100">{i18next.t("general:Back Home")}</a>
        </div>
      );
    }

    if (this.state.application === null) {
      return null;
    }

    return (
      <div className="max-w-7xl mx-auto">
        {this.renderApplication()}
      </div>
    );
  }
}

export default ApplicationEditPage;

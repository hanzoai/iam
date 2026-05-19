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
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import * as LdapBackend from "./backend/LdapBackend";
import * as Setting from "./Setting";
import * as Conf from "./Conf";
import * as Obfuscator from "./auth/Obfuscator";
import i18next from "i18next";
import {Link as LinkIcon} from "lucide-react";
import LdapTable from "./table/LdapTable";
import AccountTable from "./table/AccountTable";
import ThemeEditor from "./common/theme/ThemeEditor";
import MfaTable from "./table/MfaTable";
import {NavItemTree} from "./common/NavItemTree";
import {WidgetItemTree} from "./common/WidgetItemTree";

const NATIVE_SELECT_CLASS = "w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white";

class OrganizationEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      organizationName: props.match.params.organizationName,
      organization: null,
      applications: [],
      ldaps: null,
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
    };
  }

  UNSAFE_componentWillMount() {
    this.getOrganization();
    this.getApplications();
    this.getLdaps();
  }

  getOrganization() {
    OrganizationBackend.getOrganization("admin", this.state.organizationName)
      .then((res) => {
        if (res.status === "ok") {
          const organization = res.data;
          if (organization === null) {
            this.props.history.push("/404");
            return;
          }
          organization["enableDarkLogo"] = !!organization["logoDark"];
          this.setState({organization});
        } else {
          Setting.showMessage("error", res.msg);
        }
      });
  }

  getApplications() {
    ApplicationBackend.getApplicationsByOrganization("admin", this.state.organizationName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }
        this.setState({applications: res.data || []});
      });
  }

  getLdaps() {
    LdapBackend.getLdaps(this.state.organizationName)
      .then(res => {
        let resdata = [];
        if (res.status === "ok") {
          if (res.data !== null) {
            resdata = res.data;
          }
        }
        this.setState({ldaps: resdata});
      });
  }

  parseOrganizationField(key, value) {
    return value;
  }

  updateOrganizationField(key, value) {
    value = this.parseOrganizationField(key, value);
    const organization = this.state.organization;
    organization[key] = value;
    this.setState({organization});
  }

  updatePasswordObfuscator(key, value) {
    const organization = this.state.organization;
    if (organization.passwordObfuscatorType === "") {
      organization.passwordObfuscatorType = "Plain";
    }
    if (key === "type") {
      organization.passwordObfuscatorType = value;
      organization.passwordObfuscatorKey = Obfuscator.getRandomKeyForObfuscator(value);
    } else if (key === "key") {
      organization.passwordObfuscatorKey = value;
    }
    this.setState({organization});
  }

  renderField(label, content) {
    return (
      <div className="grid grid-cols-[180px_1fr] gap-4 items-start">
        <label className="text-sm text-gray-400 pt-2 text-right">{label} :</label>
        <div>{content}</div>
      </div>
    );
  }

  renderOrganization() {
    return (
      <div className="bg-white/[0.02] border border-white/10 rounded-xl p-6 space-y-5">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            {this.state.mode === "add" ? i18next.t("organization:New Organization") : i18next.t("organization:Edit Organization")}
          </h2>
          <div className="flex gap-2">
            <button className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.submitOrganizationEdit(false)}>{i18next.t("general:Save")}</button>
            <button className="px-4 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100" onClick={() => this.submitOrganizationEdit(true)}>{i18next.t("general:Save & Exit")}</button>
            {this.state.mode === "add" && <button className="px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.deleteOrganization()}>{i18next.t("general:Cancel")}</button>}
          </div>
        </div>

        {this.renderField(i18next.t("general:Name"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" disabled={this.state.organization.name === "built-in"} value={this.state.organization.name} onChange={e => this.updateOrganizationField("name", e.target.value)} />
        )}

        {this.renderField(i18next.t("general:Display name"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.displayName} onChange={e => this.updateOrganizationField("displayName", e.target.value)} />
        )}

        {this.renderField(i18next.t("general:Enable dark logo"),
          <button type="button" role="switch" aria-checked={this.state.organization.enableDarkLogo}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${this.state.organization.enableDarkLogo ? "bg-white" : "bg-white/20"}`}
            onClick={() => {
              const val = !this.state.organization.enableDarkLogo;
              this.updateOrganizationField("enableDarkLogo", val);
              if (!val) this.updateOrganizationField("logoDark", "");
            }}>
            <span className={`inline-block h-4 w-4 rounded-full transition-transform ${this.state.organization.enableDarkLogo ? "translate-x-6 bg-black" : "translate-x-1 bg-gray-400"}`} />
          </button>
        )}

        {this.renderField(i18next.t("general:Logo"),
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <LinkIcon size={14} className="text-gray-400" />
              <input className="flex-1 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.logo} onChange={e => this.updateOrganizationField("logo", e.target.value)} />
            </div>
            {this.state.organization.logo && <a target="_blank" rel="noreferrer" href={this.state.organization.logo}><img src={this.state.organization.logo || Setting.getLogo([""])} alt="" className="h-16 bg-white rounded p-1" /></a>}
          </div>
        )}

        {this.state.organization.enableDarkLogo && this.renderField(i18next.t("general:Logo dark"),
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <LinkIcon size={14} className="text-gray-400" />
              <input className="flex-1 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.logoDark} onChange={e => this.updateOrganizationField("logoDark", e.target.value)} />
            </div>
            {this.state.organization.logoDark && <a target="_blank" rel="noreferrer" href={this.state.organization.logoDark}><img src={this.state.organization.logoDark || Setting.getLogo(["dark"])} alt="" className="h-16 bg-[#141414] rounded p-1" /></a>}
          </div>
        )}

        {this.renderField(i18next.t("general:Favicon"),
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <LinkIcon size={14} className="text-gray-400" />
              <input className="flex-1 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.favicon} onChange={e => this.updateOrganizationField("favicon", e.target.value)} />
            </div>
            {this.state.organization.favicon && <a target="_blank" rel="noreferrer" href={this.state.organization.favicon}><img src={this.state.organization.favicon} alt="" className="h-16" /></a>}
          </div>
        )}

        {this.renderField(i18next.t("organization:Website URL"),
          <div className="flex items-center gap-2">
            <LinkIcon size={14} className="text-gray-400" />
            <input className="flex-1 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.websiteUrl} onChange={e => this.updateOrganizationField("websiteUrl", e.target.value)} />
          </div>
        )}

        {this.renderField(i18next.t("general:Password type"),
          <select className={NATIVE_SELECT_CLASS} value={this.state.organization.passwordType} onChange={e => this.updateOrganizationField("passwordType", e.target.value)}>
            {["salt", "sha512-salt", "md5-salt", "bcrypt", "pbkdf2-salt", "argon2id", "pbkdf2-django"].map(item => <option key={item} value={item}>{item}</option>)}
          </select>
        )}

        {this.renderField(i18next.t("general:Password salt"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.passwordSalt} onChange={e => this.updateOrganizationField("passwordSalt", e.target.value)} />
        )}

        {this.renderField(i18next.t("general:Password complexity options"),
          (() => {
            const opts = [
              {value: "AtLeast6", name: i18next.t("user:The password must have at least 6 characters")},
              {value: "AtLeast8", name: i18next.t("user:The password must have at least 8 characters")},
              {value: "Aa123", name: i18next.t("user:The password must contain at least one uppercase letter, one lowercase letter and one digit")},
              {value: "SpecialChar", name: i18next.t("user:The password must contain at least one special character")},
              {value: "NoRepeat", name: i18next.t("user:The password must not contain any repeated characters")},
            ];
            const selected = this.state.organization.passwordOptions ?? [];
            return (
              <div className="space-y-2">
                {opts.map(opt => (
                  <label key={opt.value} className="flex items-start gap-2 text-sm text-white">
                    <input type="checkbox" checked={selected.includes(opt.value)} onChange={e => {
                      const next = e.target.checked ? [...selected, opt.value] : selected.filter(v => v !== opt.value);
                      this.updateOrganizationField("passwordOptions", next);
                    }} />
                    <span>{opt.name}</span>
                  </label>
                ))}
              </div>
            );
          })()
        )}

        {this.renderField(i18next.t("general:Password obfuscator"),
          <select className={NATIVE_SELECT_CLASS} value={this.state.organization.passwordObfuscatorType} onChange={e => this.updatePasswordObfuscator("type", e.target.value)}>
            <option value="Plain">Plain</option>
            <option value="AES">AES</option>
            <option value="DES">DES</option>
          </select>
        )}

        {(this.state.organization.passwordObfuscatorType !== "Plain" && this.state.organization.passwordObfuscatorType !== "") &&
          this.renderField(i18next.t("general:Password obf key"),
            <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.passwordObfuscatorKey} onChange={e => this.updatePasswordObfuscator("key", e.target.value)} />
          )
        }

        {this.renderField(i18next.t("organization:Password expire days"),
          <input type="number" className="w-32 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.passwordExpireDays} onChange={e => this.updateOrganizationField("passwordExpireDays", parseInt(e.target.value) || 0)} />
        )}

        {this.renderField(i18next.t("general:Supported country codes"),
          <select multiple className={NATIVE_SELECT_CLASS + " h-32"} value={this.state.organization.countryCodes ?? []}
            onChange={e => this.updateOrganizationField("countryCodes", Array.from(e.target.selectedOptions, o => o.value))}>
            <option value="All">{i18next.t("general:All")}</option>
            {Setting.getCountryCodeData().map(country => <option key={country.code} value={country.code}>{country.name} (+{country.phone})</option>)}
          </select>
        )}

        {this.renderField(i18next.t("general:Languages"),
          <select multiple className={NATIVE_SELECT_CLASS + " h-32"}
            value={this.state.organization.languages ?? []}
            onChange={e => this.updateOrganizationField("languages", Array.from(e.target.selectedOptions, o => o.value))}>
            {Setting.Countries.map(item => <option key={item.key} value={item.key}>{item.label}</option>)}
          </select>
        )}

        {this.renderField(i18next.t("general:Default avatar"),
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <LinkIcon size={14} className="text-gray-400" />
              <input className="flex-1 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.defaultAvatar} onChange={e => this.updateOrganizationField("defaultAvatar", e.target.value)} />
            </div>
            {this.state.organization.defaultAvatar && <a target="_blank" rel="noreferrer" href={this.state.organization.defaultAvatar}><img src={this.state.organization.defaultAvatar} alt="" className="h-16" /></a>}
          </div>
        )}

        {this.renderField(i18next.t("general:Default application"),
          <select className={NATIVE_SELECT_CLASS} value={this.state.organization.defaultApplication ?? ""} onChange={e => this.updateOrganizationField("defaultApplication", e.target.value)}>
            <option value=""></option>
            {this.state.applications?.map(item => <option key={item.name} value={item.name}>{Setting.getApplicationDisplayName(item.name)}</option>)}
          </select>
        )}

        {this.renderField(i18next.t("organization:User types"),
          <input className={NATIVE_SELECT_CLASS} value={(this.state.organization.userTypes ?? []).join(",")}
            placeholder="comma,separated,tags"
            onChange={e => this.updateOrganizationField("userTypes", e.target.value.split(",").map(s => s.trim()).filter(Boolean))} />
        )}

        {this.renderField(i18next.t("organization:Tags"),
          <input className={NATIVE_SELECT_CLASS} value={(this.state.organization.tags ?? []).join(",")}
            placeholder="comma,separated,tags"
            onChange={e => this.updateOrganizationField("tags", e.target.value.split(",").map(s => s.trim()).filter(Boolean))} />
        )}

        {this.renderField(i18next.t("general:Master password"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.masterPassword} onChange={e => this.updateOrganizationField("masterPassword", e.target.value)} />
        )}

        {this.renderField(i18next.t("general:Default password"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.defaultPassword} onChange={e => this.updateOrganizationField("defaultPassword", e.target.value)} />
        )}

        {this.renderField(i18next.t("general:Master verification code"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.masterVerificationCode} onChange={e => this.updateOrganizationField("masterVerificationCode", e.target.value)} />
        )}

        {this.renderField(i18next.t("general:IP whitelist"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.ipWhitelist} onChange={e => this.updateOrganizationField("ipWhitelist", e.target.value)} />
        )}

        {this.renderField(i18next.t("organization:Init score"),
          <input type="number" className="w-32 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.initScore} onChange={e => this.updateOrganizationField("initScore", parseInt(e.target.value) || 0)} />
        )}

        {this.renderField(i18next.t("organization:Org balance"),
          <input type="number" className="w-32 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.orgBalance ?? 0} onChange={e => this.updateOrganizationField("orgBalance", parseFloat(e.target.value) || 0)} />
        )}

        {this.renderField(i18next.t("organization:User balance"),
          <input type="number" className="w-32 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" disabled value={this.state.organization.userBalance ?? 0} />
        )}

        {this.renderField(i18next.t("organization:Balance credit"),
          <input type="number" className="w-32 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.balanceCredit ?? 0} onChange={e => this.updateOrganizationField("balanceCredit", parseFloat(e.target.value) || 0)} />
        )}

        {this.renderField(i18next.t("organization:Balance currency"),
          <select className={NATIVE_SELECT_CLASS + " w-[200px]"} value={this.state.organization.balanceCurrency || "USD"} onChange={e => this.updateOrganizationField("balanceCurrency", e.target.value)}>
            {Setting.CurrencyOptions.map((item, index) => <option key={index} value={item.id}>{Setting.getCurrencyWithFlag(item.id)}</option>)}
          </select>
        )}

        {[
          ["enableSoftDeletion", i18next.t("organization:Soft deletion")],
          ["isProfilePublic", i18next.t("organization:Is profile public")],
          ["useEmailAsUsername", i18next.t("organization:Use Email as username")],
          ["enableTour", i18next.t("general:Enable tour")],
          ["disableSignin", i18next.t("application:Disable signin")],
        ].map(([key, label]) => (
          this.renderField(label,
            <button key={key} type="button" role="switch" aria-checked={this.state.organization[key]}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${this.state.organization[key] ? "bg-white" : "bg-white/20"}`}
              onClick={() => this.updateOrganizationField(key, !this.state.organization[key])}>
              <span className={`inline-block h-4 w-4 rounded-full transition-transform ${this.state.organization[key] ? "translate-x-6 bg-black" : "translate-x-1 bg-gray-400"}`} />
            </button>
          )
        ))}

        {this.renderField(i18next.t("organization:Admin navbar items"),
          <NavItemTree
            disabled={!Setting.isAdminUser(this.props.account)}
            checkedKeys={this.state.organization.navItems ?? ["all"]}
            defaultExpandedKeys={["all"]}
            onCheck={(checked) => this.updateOrganizationField("navItems", checked)}
          />
        )}

        {this.renderField(i18next.t("organization:User navbar items"),
          <NavItemTree
            disabled={!Setting.isAdminUser(this.props.account)}
            checkedKeys={this.state.organization.userNavItems ?? []}
            defaultExpandedKeys={["all"]}
            onCheck={(checked) => this.updateOrganizationField("userNavItems", checked)}
          />
        )}

        {this.renderField(i18next.t("organization:Widget items"),
          <WidgetItemTree
            disabled={!Setting.isAdminUser(this.props.account)}
            checkedKeys={this.state.organization.widgetItems ?? ["all"]}
            defaultExpandedKeys={["all"]}
            onCheck={(checked) => this.updateOrganizationField("widgetItems", checked)}
          />
        )}

        {this.renderField(i18next.t("organization:Account menu"),
          <select className={NATIVE_SELECT_CLASS} value={this.state.organization.accountMenu || "Horizontal"} onChange={e => this.updateOrganizationField("accountMenu", e.target.value)}>
            <option value="Horizontal">{i18next.t("application:Horizontal")}</option>
            <option value="Vertical">{i18next.t("application:Vertical")}</option>
          </select>
        )}

        {this.renderField(i18next.t("organization:Account items"),
          <AccountTable title={i18next.t("organization:Account items")} table={this.state.organization.accountItems} onUpdateTable={value => this.updateOrganizationField("accountItems", value)} />
        )}

        {this.renderField(i18next.t("application:MFA remember time"),
          <div className="flex items-center gap-2">
            <input type="number" className="w-32 px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.mfaRememberInHours} min={1} onChange={e => this.updateOrganizationField("mfaRememberInHours", parseInt(e.target.value) || 1)} />
            <span className="text-sm text-gray-400">Hours</span>
          </div>
        )}

        {this.renderField(i18next.t("general:MFA items"),
          <MfaTable title={i18next.t("general:MFA items")} table={this.state.organization.mfaItems ?? []} onUpdateTable={value => this.updateOrganizationField("mfaItems", value)} />
        )}

        {this.renderField(i18next.t("theme:Theme"),
          <div className="space-y-4">
            <div className="flex gap-2">
              <button className={`px-4 py-2 rounded-lg text-sm ${!(this.state.organization.themeData?.isEnabled ?? false) ? "bg-white text-black" : "bg-white/[0.05] text-white border border-white/10"}`}
                onClick={() => {
                  const theme = this.state.organization.themeData ?? {...Conf.ThemeDefault, isEnabled: false};
                  this.updateOrganizationField("themeData", {...theme, isEnabled: false});
                }}>
                {i18next.t("organization:Follow global theme")}
              </button>
              <button className={`px-4 py-2 rounded-lg text-sm ${(this.state.organization.themeData?.isEnabled ?? false) ? "bg-white text-black" : "bg-white/[0.05] text-white border border-white/10"}`}
                onClick={() => {
                  const theme = this.state.organization.themeData ?? {...Conf.ThemeDefault, isEnabled: false};
                  this.updateOrganizationField("themeData", {...theme, isEnabled: true});
                }}>
                {i18next.t("theme:Customize theme")}
              </button>
            </div>
            {this.state.organization.themeData?.isEnabled &&
              <ThemeEditor themeData={this.state.organization.themeData} onThemeChange={(_, nextThemeData) => {
                const {isEnabled} = this.state.organization.themeData ?? {...Conf.ThemeDefault, isEnabled: false};
                this.updateOrganizationField("themeData", {...nextThemeData, isEnabled});
              }} />
            }
          </div>
        )}

        {this.renderField(i18next.t("organization:LDAP attributes"),
          <select multiple className={NATIVE_SELECT_CLASS + " h-32"} value={this.state.organization.ldapAttributes ?? []}
            onChange={e => this.updateOrganizationField("ldapAttributes", Array.from(e.target.selectedOptions, o => o.value))}>
            {["uid", "cn", "mail", "email", "mobile", "displayName", "givenName", "sn", "uidNumber", "gidNumber", "homeDirectory", "loginShell", "gecos", "sshPublicKey", "memberOf", "title", "userPassword", "c", "co"].map(v => <option key={v} value={v}>{v}</option>)}
          </select>
        )}

        {this.renderField(i18next.t("general:LDAPs"),
          <LdapTable title={i18next.t("general:LDAPs")} table={this.state.ldaps} organizationName={this.state.organizationName} onUpdateTable={value => this.setState({ldaps: value})} />
        )}

        {this.renderField(i18next.t("organization:Kerberos realm"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.kerberosRealm} onChange={e => this.updateOrganizationField("kerberosRealm", e.target.value)} />
        )}

        {this.renderField(i18next.t("organization:Kerberos KDC host"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.kerberosKdcHost} onChange={e => this.updateOrganizationField("kerberosKdcHost", e.target.value)} />
        )}

        {this.renderField(i18next.t("organization:Kerberos keytab"),
          <textarea rows={4} className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" value={this.state.organization.kerberosKeytab} onChange={e => this.updateOrganizationField("kerberosKeytab", e.target.value)} />
        )}

        {this.renderField(i18next.t("organization:Kerberos service name"),
          <input className="w-full px-3 py-2 bg-white/[0.05] border border-white/10 rounded-lg text-white" placeholder="HTTP" value={this.state.organization.kerberosServiceName} onChange={e => this.updateOrganizationField("kerberosServiceName", e.target.value)} />
        )}
      </div>
    );
  }

  submitOrganizationEdit(exitAfterSave) {
    const organization = Setting.deepCopy(this.state.organization);
    organization.accountItems = organization.accountItems?.filter(accountItem => accountItem.name !== "Please select an account item");

    const passwordObfuscatorErrorMessage = Obfuscator.checkPasswordObfuscator(organization.passwordObfuscatorType, organization.passwordObfuscatorKey);
    if (passwordObfuscatorErrorMessage.length > 0) {
      Setting.showMessage("error", passwordObfuscatorErrorMessage);
      return;
    }

    OrganizationBackend.updateOrganization(this.state.organization.owner, this.state.organizationName, organization)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          if (this.props.account.organization.name === this.state.organizationName) {
            this.props.onChangeTheme(Setting.getThemeData(this.state.organization));
          }
          this.setState({organizationName: this.state.organization.name});
          window.dispatchEvent(new Event("storageOrganizationsChanged"));
          if (exitAfterSave) {
            this.props.history.push("/organizations");
          } else {
            this.props.history.push(`/organizations/${this.state.organization.name}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updateOrganizationField("name", this.state.organizationName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteOrganization() {
    OrganizationBackend.deleteOrganization(this.state.organization)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push("/organizations");
          window.dispatchEvent(new Event("storageOrganizationsChanged"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  render() {
    if (this.state.organization === null) {
      return null;
    }

    return (
      <div className="max-w-5xl mx-auto space-y-6">
        {this.renderOrganization()}
        <div className="flex gap-3">
          <button className="px-6 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.submitOrganizationEdit(false)}>{i18next.t("general:Save")}</button>
          <button className="px-6 py-2 bg-white text-black rounded-lg text-sm font-medium hover:bg-gray-100" onClick={() => this.submitOrganizationEdit(true)}>{i18next.t("general:Save & Exit")}</button>
          {this.state.mode === "add" && <button className="px-6 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/[0.05]" onClick={() => this.deleteOrganization()}>{i18next.t("general:Cancel")}</button>}
        </div>
      </div>
    );
  }
}

export default OrganizationEditPage;

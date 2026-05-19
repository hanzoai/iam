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
import * as KeyBackend from "./backend/KeyBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import * as UserBackend from "./backend/UserBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import {Button} from "./components/ui/button";
import {Card, CardContent, CardHeader, CardTitle} from "./components/ui/card";
import {Input} from "./components/ui/input";
import {Label} from "./components/ui/label";

const FIELD_LABEL = "text-sm text-muted-foreground md:text-right md:pr-4 md:pt-2";
const FIELD_ROW = "grid grid-cols-1 md:grid-cols-[160px_1fr] gap-2 mb-4";
const NATIVE_SELECT = "w-full bg-background border border-input rounded-md px-3 py-2 text-sm disabled:opacity-50";

class KeyEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      organizationName: props.match.params.organizationName,
      keyName: props.match.params.keyName,
      key: null,
      organizations: [],
      applications: [],
      users: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
    };
  }

  UNSAFE_componentWillMount() {
    this.getKey();
    this.getOrganizations();
  }

  getKey() {
    KeyBackend.getKey(this.state.organizationName, this.state.keyName)
      .then((res) => {
        if (res.data === null) {
          this.props.history.push("/404");
          return;
        }

        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }

        this.setState({
          key: res.data,
        });

        this.getApplicationsByOrganization(res.data.organization || this.state.organizationName);
        this.getUsersByOrganization(res.data.organization || this.state.organizationName);
      });
  }

  getOrganizations() {
    OrganizationBackend.getOrganizations("admin")
      .then((res) => {
        this.setState({
          organizations: res.data || [],
        });
      });
  }

  getApplicationsByOrganization(organizationName) {
    ApplicationBackend.getApplicationsByOrganization("admin", organizationName)
      .then((res) => {
        this.setState({
          applications: res.data || [],
        });
      });
  }

  getUsersByOrganization(organizationName) {
    UserBackend.getUsers(organizationName)
      .then((res) => {
        if (res.status === "ok") {
          this.setState({
            users: res.data || [],
          });
        }
      });
  }

  parseKeyField(key, value) {
    return value;
  }

  updateKeyField(key, value) {
    value = this.parseKeyField(key, value);

    const keyObj = this.state.key;
    keyObj[key] = value;
    this.setState({
      key: keyObj,
    });
  }

  renderKey() {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <CardTitle>{this.state.mode === "add" ? i18next.t("key:New Key") : i18next.t("key:Edit Key")}</CardTitle>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => this.submitKeyEdit(false)}>{i18next.t("general:Save")}</Button>
              <Button onClick={() => this.submitKeyEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
              {this.state.mode === "add" && <Button variant="outline" onClick={() => this.deleteKey()}>{i18next.t("general:Cancel")}</Button>}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Organization")}</Label>
            <select
              className={NATIVE_SELECT}
              disabled={!Setting.isAdminUser(this.props.account)}
              value={this.state.key.owner}
              onChange={e => {
                const value = e.target.value;
                this.updateKeyField("owner", value);
                this.updateKeyField("organization", value);
                this.getApplicationsByOrganization(value);
                this.getUsersByOrganization(value);
              }}
            >
              {this.state.organizations.map((organization, index) => <option key={index} value={organization.name}>{organization.name}</option>)}
            </select>
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Name")}</Label>
            <Input value={this.state.key.name} onChange={e => this.updateKeyField("name", e.target.value)} />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Display name")}</Label>
            <Input value={this.state.key.displayName} onChange={e => this.updateKeyField("displayName", e.target.value)} />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Type")}</Label>
            <select className={NATIVE_SELECT} value={this.state.key.type} onChange={e => this.updateKeyField("type", e.target.value)}>
              <option value="Organization">{i18next.t("general:Organization")}</option>
              <option value="Application">{i18next.t("general:Application")}</option>
              <option value="User">{i18next.t("general:User")}</option>
              <option value="General">{i18next.t("general:General")}</option>
            </select>
          </div>

          {this.state.key.type === "Application" && (
            <div className={FIELD_ROW}>
              <Label className={FIELD_LABEL}>{i18next.t("general:Application")}</Label>
              <select className={NATIVE_SELECT} value={this.state.key.application} onChange={e => this.updateKeyField("application", e.target.value)}>
                <option value=""></option>
                {this.state.applications.map((application, index) => <option key={index} value={application.name}>{application.name}</option>)}
              </select>
            </div>
          )}

          {this.state.key.type === "User" && (
            <div className={FIELD_ROW}>
              <Label className={FIELD_LABEL}>{i18next.t("general:User")}</Label>
              <select className={NATIVE_SELECT} value={this.state.key.user} onChange={e => this.updateKeyField("user", e.target.value)}>
                <option value=""></option>
                {this.state.users.map((user, index) => <option key={index} value={user.name}>{user.name}</option>)}
              </select>
            </div>
          )}

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("key:Access key")}</Label>
            <Input value={this.state.key.accessKey} readOnly />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("key:Access secret")}</Label>
            <Input type="password" value={this.state.key.accessSecret} readOnly />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Expire time")}</Label>
            <Input
              type="datetime-local"
              value={this.state.key.expireTime ? this.state.key.expireTime.substring(0, 16) : ""}
              onChange={e => this.updateKeyField("expireTime", e.target.value ? new Date(e.target.value).toISOString() : "")}
            />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:State")}</Label>
            <select className={NATIVE_SELECT} value={this.state.key.state} onChange={e => this.updateKeyField("state", e.target.value)}>
              <option value="Active">{i18next.t("subscription:Active")}</option>
              <option value="Inactive">{i18next.t("key:Inactive")}</option>
            </select>
          </div>
        </CardContent>
      </Card>
    );
  }

  submitKeyEdit(exitAfterSave) {
    const key = Setting.deepCopy(this.state.key);
    KeyBackend.updateKey(this.state.organizationName, this.state.keyName, key)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            organizationName: this.state.key.owner,
            keyName: this.state.key.name,
          });

          if (exitAfterSave) {
            this.props.history.push("/keys");
          } else {
            this.props.history.push(`/keys/${this.state.key.owner}/${this.state.key.name}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updateKeyField("owner", this.state.organizationName);
          this.updateKeyField("name", this.state.keyName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteKey() {
    KeyBackend.deleteKey(this.state.key)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push("/keys");
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  render() {
    return (
      <div>
        {this.state.key !== null ? this.renderKey() : null}
        <div className="mt-5 ml-10 flex gap-3">
          <Button variant="outline" size="lg" onClick={() => this.submitKeyEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button size="lg" onClick={() => this.submitKeyEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
        </div>
      </div>
    );
  }
}

export default KeyEditPage;

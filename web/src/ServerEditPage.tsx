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
import {Link as LinkIcon} from "lucide-react";
import * as ServerBackend from "./backend/ServerBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as ApplicationBackend from "./backend/ApplicationBackend";
import ToolTable from "./ToolTable";
import {Button} from "./components/ui/button";
import {Card, CardContent, CardHeader, CardTitle} from "./components/ui/card";
import {Input} from "./components/ui/input";
import {Label} from "./components/ui/label";

const FIELD_LABEL = "text-sm text-muted-foreground md:text-right md:pr-4 md:pt-2";
const FIELD_ROW = "grid grid-cols-1 md:grid-cols-[160px_1fr] gap-2 mb-4";

class ServerEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      serverName: props.match.params.serverName,
      owner: props.match.params.organizationName,
      server: null,
      organizations: [],
      applications: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
    };
  }

  UNSAFE_componentWillMount() {
    this.getServer();
    this.getOrganizations();
    this.getApplications(this.state.owner);
  }

  getServer() {
    ServerBackend.getServer(this.state.server?.owner || this.state.owner, this.state.serverName)
      .then((res) => {
        if (res.data === null) {
          this.props.history.push("/404");
          return;
        }

        if (res.status === "ok") {
          this.setState({
            server: res.data,
          });
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${res.msg}`);
        }
      });
  }

  getOrganizations() {
    if (Setting.isAdminUser(this.props.account)) {
      OrganizationBackend.getOrganizations("admin")
        .then((res) => {
          this.setState({
            organizations: res.data || [],
          });
        });
    }
  }

  getApplications(owner) {
    ApplicationBackend.getApplicationsByOrganization("admin", owner)
      .then((res) => {
        this.setState({
          applications: res.data || [],
        });
      });
  }

  updateServerField(key, value) {
    const server = this.state.server;
    if (key === "owner" && server.owner !== value) {
      server.application = "";
      this.getApplications(value);
    }

    server[key] = value;
    this.setState({
      server: server,
    });
  }

  submitServerEdit(willExit) {
    const server = Setting.deepCopy(this.state.server);
    ServerBackend.updateServer(this.state.owner, this.state.serverName, server)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully modified"));
          if (willExit) {
            this.props.history.push("/servers");
          } else {
            this.setState({
              mode: "edit",
              owner: server.owner,
              serverName: server.name,
            }, () => {this.getServer();});
            this.props.history.push(`/servers/${server.owner}/${server.name}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to update")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteServer() {
    ServerBackend.deleteServer(this.state.server)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          this.props.history.push("/servers");
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  renderServer() {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <CardTitle>
              {this.state.mode === "add" ? i18next.t("server:New MCP Server") : i18next.t("server:Edit MCP Server")}
            </CardTitle>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => this.submitServerEdit(false)}>{i18next.t("general:Save")}</Button>
              <Button onClick={() => this.submitServerEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
              {this.state.mode === "add" && <Button variant="outline" onClick={() => this.deleteServer()}>{i18next.t("general:Cancel")}</Button>}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Organization")}</Label>
            <select
              className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm disabled:opacity-50"
              disabled={!Setting.isAdminUser(this.props.account)}
              value={this.state.server.owner}
              onChange={e => this.updateServerField("owner", e.target.value)}
            >
              {this.state.organizations.map((organization, index) => <option key={index} value={organization.name}>{organization.name}</option>)}
            </select>
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Name")}</Label>
            <Input value={this.state.server.name} onChange={e => this.updateServerField("name", e.target.value)} />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Display name")}</Label>
            <Input value={this.state.server.displayName} onChange={e => this.updateServerField("displayName", e.target.value)} />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:URL")}</Label>
            <div className="flex items-center gap-2">
              <LinkIcon className="h-4 w-4 text-muted-foreground" />
              <Input className="flex-1" value={this.state.server.url} onChange={e => this.updateServerField("url", e.target.value)} />
            </div>
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("token:Access token")}</Label>
            <Input type="password" placeholder="***" value={this.state.server.token} onChange={e => this.updateServerField("token", e.target.value)} />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Application")}</Label>
            <select
              className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm"
              value={this.state.server.application}
              onChange={e => this.updateServerField("application", e.target.value)}
            >
              <option value=""></option>
              {this.state.applications.map((application, index) => <option key={index} value={application.name}>{application.name}</option>)}
            </select>
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("general:Tool")}</Label>
            <ToolTable
              tools={this.state.server?.tools || []}
              onUpdateTable={(value) => this.updateServerField("tools", value)}
            />
          </div>

          <div className={FIELD_ROW}>
            <Label className={FIELD_LABEL}>{i18next.t("provider:Base URL")}</Label>
            <div className="flex items-center gap-2">
              <LinkIcon className="h-4 w-4 text-muted-foreground" />
              <Input className="flex-1" readOnly value={`${window.location.origin}/v1/iam/server/${this.state.server.owner}/${this.state.server.name}`} />
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  render() {
    if (this.state.server === null) {
      return null;
    }

    return (
      <div>
        {this.renderServer()}
      </div>
    );
  }
}

export default ServerEditPage;

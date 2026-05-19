// Copyright 2022 The Hanzo Authors. All Rights Reserved.
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
import * as SystemBackend from "./backend/SystemInfo";
import React from "react";
import * as Setting from "./Setting";
import * as TourConfig from "./TourConfig";
import i18next from "i18next";
import PrometheusInfoTable from "./table/PrometheusInfoTable";
import {Card, CardContent, CardHeader, CardTitle} from "./components/ui/card";
import {Progress} from "./components/ui/progress";
import {Spinner} from "./components/ui/spinner";

class SystemInfo extends React.Component {

  constructor(props) {
    super(props);
    this.state = {
      systemInfo: {cpuUsage: [], memoryUsed: 0, memoryTotal: 0},
      versionInfo: {},
      prometheusInfo: {apiThroughput: [], apiLatency: [], totalThroughput: 0},
      intervalId: null,
      loading: true,
      isTourVisible: TourConfig.getTourVisible(),
    };
  }

  UNSAFE_componentWillMount() {
    SystemBackend.getSystemInfo("").then(res => {
      this.setState({
        loading: false,
      });

      if (res.status === "ok") {
        this.setState({
          systemInfo: res.data,
        });
      } else {
        Setting.showMessage("error", res.msg);
        this.stopTimer();
      }

      const id = setInterval(() => {
        SystemBackend.getSystemInfo("").then(res => {
          this.setState({
            loading: false,
          });

          if (res.status === "ok") {
            this.setState({
              systemInfo: res.data,
            });
          } else {
            Setting.showMessage("error", res.msg);
            this.stopTimer();
          }
        }).catch(error => {
          Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${error}`);
          this.stopTimer();
        });
        SystemBackend.getPrometheusInfo().then(res => {
          this.setState({
            prometheusInfo: res.data,
          });
        });
      }, 1000 * 2);

      this.setState({intervalId: id});
    }).catch(error => {
      Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${error}`);
      this.stopTimer();
    });

    SystemBackend.getVersionInfo().then(res => {
      if (res.status === "ok") {
        this.setState({
          versionInfo: res.data,
        });
      } else {
        Setting.showMessage("error", res.msg);
        this.stopTimer();
      }
    }).catch(err => {
      Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${err}`);
      this.stopTimer();
    });
  }

  componentDidMount() {
    window.addEventListener("storageTourChanged", this.handleTourChange);
  }

  handleTourChange = () => {
    this.setState({isTourVisible: TourConfig.getTourVisible()});
  };

  stopTimer() {
    if (this.state.intervalId !== null) {
      clearInterval(this.state.intervalId);
    }
  }

  componentWillUnmount() {
    this.stopTimer();
    window.removeEventListener("storageTourChanged", this.handleTourChange);
  }

  setIsTourVisible = () => {
    TourConfig.setIsTourVisible(false);
    this.setState({isTourVisible: false});
  };

  renderInfoCard(id, title, body) {
    return (
      <Card id={id} className="text-center h-full">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent>{body}</CardContent>
      </Card>
    );
  }

  render() {
    const cpuUi = this.state.systemInfo.cpuUsage?.length <= 0 ? i18next.t("general:Failed to get") :
      this.state.systemInfo.cpuUsage.map((usage, i) => {
        const percent = Number(usage.toFixed(1));
        return (
          <div key={i} className="flex items-center gap-2 mb-2">
            <Progress value={percent} className="flex-1" />
            <span className="text-sm text-muted-foreground w-12 text-right">{percent}%</span>
          </div>
        );
      });

    const memPercent = Number((Number(this.state.systemInfo.memoryUsed) / Number(this.state.systemInfo.memoryTotal) * 100).toFixed(2));
    const memUi = this.state.systemInfo.memoryUsed && this.state.systemInfo.memoryTotal && this.state.systemInfo.memoryTotal <= 0 ? i18next.t("general:Failed to get") :
      <div>
        {Setting.getFriendlyFileSize(this.state.systemInfo.memoryUsed)} / {Setting.getFriendlyFileSize(this.state.systemInfo.memoryTotal)}
        <br /> <br />
        <div className="flex items-center gap-2">
          <Progress value={memPercent} className="flex-1" />
          <span className="text-sm text-muted-foreground w-12 text-right">{memPercent}%</span>
        </div>
      </div>;
    const latencyUi = this.state.prometheusInfo?.apiLatency === null || this.state.prometheusInfo?.apiLatency?.length <= 0 ? <Spinner size="lg" /> :
      <PrometheusInfoTable prometheusInfo={this.state.prometheusInfo} table={"latency"} />;
    const throughputUi = this.state.prometheusInfo?.apiThroughput === null || this.state.prometheusInfo?.apiThroughput?.length <= 0 ? <Spinner size="lg" /> :
      <PrometheusInfoTable prometheusInfo={this.state.prometheusInfo} table={"throughput"} />;
    const link = this.state.versionInfo?.version !== "" ? `https://github.com/hanzoai/iam/releases/tag/${this.state.versionInfo?.version}` : "";
    let versionText = this.state.versionInfo?.version !== "" ? this.state.versionInfo?.version : i18next.t("system:Unknown version");
    if (this.state.versionInfo?.commitOffset > 0) {
      versionText += ` (ahead+${this.state.versionInfo?.commitOffset})`;
    }

    const aboutCard = (
      <Card id="about-card" className="text-center">
        <CardHeader>
          <CardTitle>{i18next.t("system:About")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div>{i18next.t("system:An Identity and Access Management (IAM) / Single-Sign-On (SSO) platform with web UI supporting OAuth 2.0, OIDC, SAML and CAS")}</div>
          GitHub: <a target="_blank" rel="noreferrer" href="https://github.com/hanzoai/iam">IAM</a>
          <br />
          {i18next.t("system:Version")}: <a target="_blank" rel="noreferrer" href={link}>{versionText}</a>
          <br />
          {i18next.t("system:Official website")}: <a target="_blank" rel="noreferrer" href="https://github.com/hanzoai/iam">github.com/hanzoai/iam</a>
          <br />
          {i18next.t("system:Community")}: <a target="_blank" rel="noreferrer" href="https://github.com/hanzoai/iam/discussions">Get in Touch!</a>
        </CardContent>
      </Card>
    );

    if (!Setting.isMobile()) {
      return (
        // TODO(rip-antd): Tour walkthrough disabled
        <div className="grid grid-cols-12 gap-3">
          <div className="col-span-3"></div>
          <div className="col-span-6 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              {this.renderInfoCard("cpu-card", i18next.t("system:CPU Usage"), this.state.loading ? <Spinner size="lg" /> : cpuUi)}
              {this.renderInfoCard("memory-card", i18next.t("system:Memory Usage"), this.state.loading ? <Spinner size="lg" /> : memUi)}
            </div>
            {this.renderInfoCard("latency-card", i18next.t("system:API Latency"), this.state.loading ? <Spinner size="lg" /> : latencyUi)}
            {this.renderInfoCard("throughput-card", i18next.t("system:API Throughput"), this.state.loading ? <Spinner size="lg" /> : throughputUi)}
            <hr className="border-border my-4" />
            {aboutCard}
          </div>
          <div className="col-span-3"></div>
        </div>
      );
    } else {
      return (
        <div className="space-y-4">
          {this.renderInfoCard(null, i18next.t("system:CPU Usage"), this.state.loading ? <Spinner size="lg" /> : cpuUi)}
          {this.renderInfoCard(null, i18next.t("system:Memory Usage"), this.state.loading ? <Spinner size="lg" /> : memUi)}
          {aboutCard}
        </div>
      );
    }
  }
}

export default SystemInfo;

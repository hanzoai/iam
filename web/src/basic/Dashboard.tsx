// @ts-nocheck
// Copyright 2023 The Hanzo Authors. All Rights Reserved.
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

import {TrendingUp} from "lucide-react";
import * as echarts from "echarts";
import i18next from "i18next";
import React from "react";
import * as DashboardBackend from "../backend/DashboardBackend";
import * as Setting from "../Setting";
import * as TourConfig from "../TourConfig";

const Dashboard = (props) => {
  const [dashboardData, setDashboardData] = React.useState(null);

  React.useEffect(() => {
    window.addEventListener("storageOrganizationChanged", handleOrganizationChange);
    return () => window.removeEventListener("storageOrganizationChanged", handleOrganizationChange);
  }, [props.owner]);

  React.useEffect(() => {
    if (!Setting.isLocalAdminUser(props.account)) {
      props.history.push("/apps");
    }
  }, [props.account]);

  const getOrganizationName = () => {
    let organization = localStorage.getItem("organization") === "All" ? "" : localStorage.getItem("organization");
    if (!Setting.isAdminUser(props.account) && Setting.isLocalAdminUser(props.account)) {
      organization = props.account.owner;
    }
    if (!organization) {
      organization = props.account.owner;
    }
    return organization;
  };

  React.useEffect(() => {
    if (!Setting.isLocalAdminUser(props.account)) return;
    const organization = getOrganizationName();
    DashboardBackend.getDashboard(organization).then((res) => {
      if (res.status === "ok") {
        setDashboardData(res.data);
      } else {
        Setting.showMessage("error", res.msg);
      }
    });
  }, [props.owner]);

  const handleOrganizationChange = () => {
    if (!Setting.isLocalAdminUser(props.account)) return;
    setDashboardData(null);
    const organization = getOrganizationName();
    DashboardBackend.getDashboard(organization).then((res) => {
      if (res.status === "ok") {
        setDashboardData(res.data);
      } else {
        Setting.showMessage("error", res.msg);
      }
    });
  };

  const renderEChart = () => {
    const chartDom = document.getElementById("echarts-chart");

    if (dashboardData === null) {
      if (chartDom) {
        const instance = echarts.getInstanceByDom(chartDom);
        if (instance) instance.dispose();
      }
      return (
        <div className="flex justify-center items-center">
          <span className="text-zinc-400 pt-[10%]">{i18next.t("login:Loading")}</span>
        </div>
      );
    }

    const myChart = echarts.init(chartDom);
    const currentDate = new Date();
    const dateArray = [];
    for (let i = 30; i >= 0; i--) {
      const date = new Date(currentDate);
      date.setDate(date.getDate() - i);
      const month = parseInt(date.getMonth()) + 1;
      const day = parseInt(date.getDate());
      dateArray.push(`${month}-${day}`);
    }
    const option = {
      title: {text: i18next.t("home:Past 30 Days"), textStyle: {color: "#fff"}},
      tooltip: {trigger: "axis"},
      legend: {data: [
        i18next.t("general:Users"), i18next.t("application:Providers"), i18next.t("general:Applications"),
        i18next.t("general:Organizations"), i18next.t("general:Subscriptions"), i18next.t("general:Roles"),
        i18next.t("general:Groups"), i18next.t("general:Resources"), i18next.t("general:Certs"),
        i18next.t("general:Permissions"), i18next.t("general:Transactions"), i18next.t("general:Models"),
        i18next.t("general:Adapters"), i18next.t("general:Enforcers"),
      ], top: "10%", textStyle: {color: "#a1a1aa"}},
      grid: {left: "3%", right: "4%", bottom: "0", top: "30%", containLabel: true},
      xAxis: {type: "category", boundaryGap: false, data: dateArray, axisLabel: {color: "#71717a"}},
      yAxis: {type: "value", axisLabel: {color: "#71717a"}},
      series: [
        {name: i18next.t("general:Organizations"), type: "line", data: dashboardData.organizationCounts},
        {name: i18next.t("general:Users"), type: "line", data: dashboardData.userCounts},
        {name: i18next.t("application:Providers"), type: "line", data: dashboardData.providerCounts},
        {name: i18next.t("general:Applications"), type: "line", data: dashboardData.applicationCounts},
        {name: i18next.t("general:Subscriptions"), type: "line", data: dashboardData.subscriptionCounts},
        {name: i18next.t("general:Roles"), type: "line", data: dashboardData.roleCounts},
        {name: i18next.t("general:Groups"), type: "line", data: dashboardData.groupCounts},
        {name: i18next.t("general:Resources"), type: "line", data: dashboardData.resourceCounts},
        {name: i18next.t("general:Certs"), type: "line", data: dashboardData.certCounts},
        {name: i18next.t("general:Permissions"), type: "line", data: dashboardData.permissionCounts},
        {name: i18next.t("general:Transactions"), type: "line", data: dashboardData.transactionCounts},
        {name: i18next.t("general:Models"), type: "line", data: dashboardData.modelCounts},
        {name: i18next.t("general:Adapters"), type: "line", data: dashboardData.adapterCounts},
        {name: i18next.t("general:Enforcers"), type: "line", data: dashboardData.enforcerCounts},
      ],
    };
    myChart.setOption(option);

    const stats = [
      {label: i18next.t("home:Total users"), value: dashboardData.userCounts[30]},
      {label: i18next.t("home:New users today"), value: dashboardData.userCounts[30] - dashboardData.userCounts[29], showArrow: true},
      {label: i18next.t("home:New users past 7 days"), value: dashboardData.userCounts[30] - dashboardData.userCounts[23], showArrow: true},
      {label: i18next.t("home:New users past 30 days"), value: dashboardData.userCounts[30] - dashboardData.userCounts[0], showArrow: true},
    ];

    return (
      <div id="statistic" className="flex flex-wrap justify-center gap-6 mb-4">
        {stats.map((stat) => (
          <div key={stat.label} className="border border-zinc-800 rounded-lg bg-zinc-900/30 p-6 w-[220px]">
            <p className="text-sm text-zinc-400 mb-2">{stat.label}</p>
            <p className="text-3xl font-semibold text-white flex items-center gap-2">
              {stat.showArrow && <TrendingUp className="w-5 h-5 text-green-400" />}
              {stat.value}
            </p>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="flex justify-center flex-col items-center">
      {renderEChart()}
      <div id="echarts-chart" className="w-4/5 h-[400px] text-center mt-5" />
    </div>
  );
};

export default Dashboard;

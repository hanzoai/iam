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

// @ts-nocheck
import React from "react";
import i18next from "i18next";

function PrometheusInfoTable({table, prometheusInfo}) {
  if (table === "latency") {
    const data = prometheusInfo?.apiLatency || [];
    return (
      <div className="h-[300px] overflow-auto">
        <div className="border border-white/10 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Method")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("system:Count")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("system:Latency")}(ms)</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row, i) => (
                <tr key={i} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                  <td className="px-4 py-2 text-white">{row.name}</td>
                  <td className="px-4 py-2 text-white">{row.method}</td>
                  <td className="px-4 py-2 text-white">{row.count}</td>
                  <td className="px-4 py-2 text-white">{row.latency}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  } else if (table === "throughput") {
    const data = prometheusInfo?.apiThroughput || [];
    return (
      <div className="h-[300px] overflow-auto">
        <p className="text-sm text-gray-300 mb-2">{i18next.t("system:Total Throughput")}: {prometheusInfo?.totalThroughput}</p>
        <div className="border border-white/10 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Name")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("general:Method")}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">{i18next.t("system:Throughput")}</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row, i) => (
                <tr key={i} className="border-b border-white/[0.05] hover:bg-white/[0.02]">
                  <td className="px-4 py-2 text-white">{row.name}</td>
                  <td className="px-4 py-2 text-white">{row.method}</td>
                  <td className="px-4 py-2 text-white">{row.throughput}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  return null;
}

export default PrometheusInfoTable;

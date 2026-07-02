// Copyright 2023 The Casdoor Authors. All Rights Reserved.
// Modifications Copyright 2025 Hanzo AI, Inc.
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

package object

import (
	"fmt"
	"time"

	"github.com/luxfi/metric"
)

type PrometheusInfo struct {
	ApiThroughput   []GaugeVecInfo     `json:"apiThroughput"`
	ApiLatency      []HistogramVecInfo `json:"apiLatency"`
	TotalThroughput float64            `json:"totalThroughput"`
}

type GaugeVecInfo struct {
	Method     string  `json:"method"`
	Name       string  `json:"name"`
	Throughput float64 `json:"throughput"`
}

type HistogramVecInfo struct {
	Method  string `json:"method"`
	Name    string `json:"name"`
	Count   uint64 `json:"count"`
	Latency string `json:"latency"`
}

var (
	ApiThroughput = metric.NewGaugeVec(metric.GaugeOpts{
		Name: "iam_api_throughput",
		Help: "The throughput of each api access",
	}, []string{"path", "method"})

	ApiLatency = metric.NewHistogramVec(metric.HistogramOpts{
		Name: "iam_api_latency",
		Help: "API processing latency in milliseconds",
	}, []string{"path", "method"})

	CpuUsage = metric.NewGaugeVec(metric.GaugeOpts{
		Name: "iam_cpu_usage",
		Help: "IAM cpu usage",
	}, []string{"cpuNum"})

	MemoryUsage = metric.NewGaugeVec(metric.GaugeOpts{
		Name: "iam_memory_usage",
		Help: "IAM memory usage in Byte",
	}, []string{"type"})

	TotalThroughput = metric.NewGauge(metric.GaugeOpts{
		Name: "iam_total_throughput",
		Help: "The total throughput of iam",
	})
)

func ClearThroughputPerSecond() {
	ticker := time.NewTicker(time.Second)
	for range ticker.C {
		ApiThroughput.Reset()
		TotalThroughput.Set(0)
	}
}

func GetPrometheusInfo() (*PrometheusInfo, error) {
	res := &PrometheusInfo{}
	families, err := metric.DefaultRegistry.Gather()
	if err != nil {
		return nil, err
	}
	for _, family := range families {
		switch family.Name {
		case "iam_api_throughput":
			res.ApiThroughput = getGaugeVecInfo(family)
		case "iam_api_latency":
			res.ApiLatency = getHistogramVecInfo(family)
		case "iam_total_throughput":
			if len(family.Metrics) > 0 {
				res.TotalThroughput = family.Metrics[0].Value.Value
			}
		}
	}
	return res, nil
}

func getHistogramVecInfo(family *metric.MetricFamily) []HistogramVecInfo {
	out := make([]HistogramVecInfo, 0, len(family.Metrics))
	for _, m := range family.Metrics {
		sampleCount := m.Value.SampleCount
		sampleSum := m.Value.SampleSum
		var latency float64
		if sampleCount > 0 {
			latency = sampleSum / float64(sampleCount)
		}
		out = append(out, HistogramVecInfo{
			Method:  labelValue(m.Labels, 0),
			Name:    labelValue(m.Labels, 1),
			Count:   sampleCount,
			Latency: fmt.Sprintf("%.3f", latency),
		})
	}
	return out
}

func getGaugeVecInfo(family *metric.MetricFamily) []GaugeVecInfo {
	out := make([]GaugeVecInfo, 0, len(family.Metrics))
	for _, m := range family.Metrics {
		out = append(out, GaugeVecInfo{
			Method:     labelValue(m.Labels, 0),
			Name:       labelValue(m.Labels, 1),
			Throughput: m.Value.Value,
		})
	}
	return out
}

func labelValue(labels []metric.LabelPair, idx int) string {
	if idx < 0 || idx >= len(labels) {
		return ""
	}
	return labels[idx].Value
}

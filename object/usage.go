// Copyright 2025 The Hanzo Authors. All Rights Reserved.
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

	"github.com/hanzoai/iam/util"
)

// UsageRecord tracks API usage per request for billing and observability.
// Each model inference call creates one record.
type UsageRecord struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100) index" json:"createdTime"`

	User         string `xorm:"varchar(200) index" json:"user"`         // owner/username
	Application  string `xorm:"varchar(100)" json:"application"`        // app that made the request
	Organization string `xorm:"varchar(100) index" json:"organization"` // org for billing
	Project      string `xorm:"varchar(100) index" json:"project"`      // project within org

	Model    string `xorm:"varchar(200)" json:"model"`    // user-facing model name
	Provider string `xorm:"varchar(100)" json:"provider"` // upstream provider name

	PromptTokens     int `json:"promptTokens"`
	CompletionTokens int `json:"completionTokens"`
	TotalTokens      int `json:"totalTokens"`

	Cost     float64 `xorm:"DECIMAL(10,6)" json:"cost"`    // cost in USD
	Currency string  `xorm:"varchar(10)" json:"currency"`  // currency code
	Premium  bool    `json:"premium"`                      // premium model flag
	Stream   bool    `json:"stream"`                       // was streaming enabled
	Status   string  `xorm:"varchar(20)" json:"status"`    // success, error
	ErrorMsg string  `xorm:"varchar(500)" json:"errorMsg"` // error message if failed

	ClientIP  string `xorm:"varchar(100)" json:"clientIp"`  // request source IP
	RequestID string `xorm:"varchar(100)" json:"requestId"` // unique request ID
}

func GetUsageRecordCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&UsageRecord{Owner: owner})
}

func GetUsageRecords(owner string) ([]*UsageRecord, error) {
	records := []*UsageRecord{}
	err := ormer.Engine.Desc("created_time").Find(&records, &UsageRecord{Owner: owner})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func GetPaginationUsageRecords(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*UsageRecord, error) {
	records := []*UsageRecord{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&records, &UsageRecord{Owner: owner})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func GetUserUsageRecords(owner, user string) ([]*UsageRecord, error) {
	records := []*UsageRecord{}
	err := ormer.Engine.Desc("created_time").Find(&records, &UsageRecord{Owner: owner, User: user})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func GetUsageRecord(id string) (*UsageRecord, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}

	record := UsageRecord{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&record)
	if err != nil {
		return nil, err
	}
	if existed {
		return &record, nil
	}
	return nil, nil
}

func AddUsageRecord(record *UsageRecord) (bool, error) {
	if record.Name == "" {
		record.Name = util.GenerateId()
	}
	if record.CreatedTime == "" {
		record.CreatedTime = util.GetCurrentTime()
	}

	affected, err := ormer.Engine.Insert(record)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func AddUsageRecords(records []*UsageRecord) (bool, error) {
	if len(records) == 0 {
		return false, nil
	}
	for _, record := range records {
		if record.Name == "" {
			record.Name = util.GenerateId()
		}
		if record.CreatedTime == "" {
			record.CreatedTime = util.GetCurrentTime()
		}
	}

	affected, err := ormer.Engine.Insert(&records)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func GetProjectUsageRecords(owner, project string) ([]*UsageRecord, error) {
	records := []*UsageRecord{}
	err := ormer.Engine.Desc("created_time").Find(&records, &UsageRecord{Owner: owner, Project: project})
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetProjectUsageSummary returns aggregated usage stats for a project within a time range.
func GetProjectUsageSummary(owner, project, startTime, endTime string) (map[string]interface{}, error) {
	return GetUsageSummaryFiltered(owner, "", project, startTime, endTime)
}

// GetUsageSummary returns aggregated usage stats for a user within a time range.
func GetUsageSummary(owner, user, startTime, endTime string) (map[string]interface{}, error) {
	return GetUsageSummaryFiltered(owner, user, "", startTime, endTime)
}

// GetUsageSummaryFiltered returns aggregated usage stats with optional user and project filters.
func GetUsageSummaryFiltered(owner, user, project, startTime, endTime string) (map[string]interface{}, error) {
	type summary struct {
		TotalRequests    int64   `json:"totalRequests"`
		TotalTokens      int64   `json:"totalTokens"`
		TotalCost        float64 `json:"totalCost"`
		PromptTokens     int64   `json:"promptTokens"`
		CompletionTokens int64   `json:"completionTokens"`
	}

	var s summary
	session := ormer.Engine.Table(&UsageRecord{}).Where("owner = ?", owner)
	if user != "" {
		session = session.Where("user = ?", user)
	}
	if project != "" {
		session = session.Where("project = ?", project)
	}
	if startTime != "" {
		session = session.Where("created_time >= ?", startTime)
	}
	if endTime != "" {
		session = session.Where("created_time <= ?", endTime)
	}

	_, err := session.Select("COUNT(*) as total_requests, COALESCE(SUM(total_tokens),0) as total_tokens, COALESCE(SUM(cost),0) as total_cost, COALESCE(SUM(prompt_tokens),0) as prompt_tokens, COALESCE(SUM(completion_tokens),0) as completion_tokens").Get(&s)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"totalRequests":    s.TotalRequests,
		"totalTokens":      s.TotalTokens,
		"totalCost":        s.TotalCost,
		"promptTokens":     s.PromptTokens,
		"completionTokens": s.CompletionTokens,
	}, nil
}

func (record *UsageRecord) GetId() string {
	return fmt.Sprintf("%s/%s", record.Owner, record.Name)
}

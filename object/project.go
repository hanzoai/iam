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

// Project represents a project within an organization.
// Organizations contain projects, which scope applications and usage tracking.
type Project struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	DisplayName  string   `xorm:"varchar(100)" json:"displayName"`
	Description  string   `xorm:"varchar(500)" json:"description"`
	Organization string   `xorm:"varchar(100) index" json:"organization"`
	Tags         []string `xorm:"mediumtext" json:"tags"`
	Metadata     string   `xorm:"mediumtext" json:"metadata"`
	IsDefault    bool     `json:"isDefault"`
}

func GetProjectCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Project{Owner: owner})
}

func GetProjects(owner string) ([]*Project, error) {
	projects := []*Project{}
	err := ormer.Engine.Desc("created_time").Find(&projects, &Project{Owner: owner})
	if err != nil {
		return nil, err
	}
	return projects, nil
}

func GetPaginationProjects(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Project, error) {
	projects := []*Project{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&projects, &Project{Owner: owner})
	if err != nil {
		return nil, err
	}
	return projects, nil
}

func GetOrganizationProjects(organization string) ([]*Project, error) {
	projects := []*Project{}
	err := ormer.Engine.Desc("created_time").Find(&projects, &Project{Organization: organization})
	if err != nil {
		return nil, err
	}
	return projects, nil
}

func getProject(owner string, name string) (*Project, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	project := Project{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&project)
	if err != nil {
		return nil, err
	}

	if existed {
		return &project, nil
	}

	return nil, nil
}

func GetProject(id string) (*Project, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getProject(owner, name)
}

func AddProject(project *Project) (bool, error) {
	if project.CreatedTime == "" {
		project.CreatedTime = util.GetCurrentTime()
	}

	affected, err := ormer.Engine.Insert(project)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func UpdateProject(id string, project *Project) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}

	existing, err := getProject(owner, name)
	if err != nil {
		return false, err
	}
	if existing == nil {
		return false, nil
	}

	affected, err := ormer.Engine.ID(PK{owner, name}).AllCols().Update(project)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteProject(project *Project) (bool, error) {
	affected, err := ormer.Engine.ID(PK{project.Owner, project.Name}).Delete(&Project{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (project *Project) GetId() string {
	return fmt.Sprintf("%s/%s", project.Owner, project.Name)
}

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

// GetDefaultProject returns an organization's default project — the row whose
// Organization matches and IsDefault is true — or nil when the org has none.
// It is read at token-mint time to stamp the `project` claim, so it queries the
// indexed Organization column and never falls back to a non-default project.
func GetDefaultProject(organization string) (*Project, error) {
	if organization == "" {
		return nil, nil
	}

	project := Project{}
	existed, err := ormer.Engine.Where("organization = ?", organization).And("is_default = ?", true).Get(&project)
	if err != nil {
		return nil, err
	}

	if existed {
		return &project, nil
	}

	return nil, nil
}

// DefaultProjectName is the canonical name of an organization's default
// project. cloud's principal.IsDefaultProject treats an absent / "" / "default"
// project claim as the ONE default scope and keeps keys un-suffixed; any OTHER
// name is minted as a real NAMED claim and — once caps are seeded — hard-402
// enforced. So this name is load-bearing: every org's seeded default MUST use it
// verbatim to keep the principal SOFT until someone creates a NAMED project.
const DefaultProjectName = "default"

// newDefaultProject builds an organization's default project. Owner AND
// Organization are BOTH the org slug: the `project` claim resolves on the
// Organization column (GetDefaultProject) while CRUD lists by the Owner PK
// (GetProjects) — they must not diverge. IsDefault marks it the token-mint
// target for GetDefaultProject.
func newDefaultProject(organization string) *Project {
	return &Project{
		Owner:        organization,
		Name:         DefaultProjectName,
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "Default",
		Organization: organization,
		IsDefault:    true,
	}
}

// EnsureDefaultProject seeds an organization's default project when it lacks
// one. It is the ONE way an org gets its default project — composed into every
// org-creation path and the boot backfill. Idempotent and live-safe: it ADDS a
// row only when the org has neither an IsDefault project nor a "default"-named
// project (which would collide on the (Owner, Name) PK); it NEVER modifies an
// existing project. Returns whether it created a row.
func EnsureDefaultProject(organization string) (bool, error) {
	if organization == "" {
		return false, nil
	}

	existing, err := GetDefaultProject(organization)
	if err != nil {
		return false, err
	}
	if existing != nil {
		return false, nil
	}

	named, err := getProject(organization, DefaultProjectName)
	if err != nil {
		return false, err
	}
	if named != nil {
		return false, nil
	}

	return AddProject(newDefaultProject(organization))
}

// BackfillDefaultProjects seeds a default project for every organization that
// lacks one. One-shot, idempotent and live-safe — safe to run on every boot:
// orgs already carrying a default (or "default"-named) project are skipped and
// no existing project is ever touched. Returns the number of projects created.
func BackfillDefaultProjects() (int, error) {
	organizations := []*Organization{}
	if err := ormer.Engine.Find(&organizations); err != nil {
		return 0, err
	}

	created := 0
	for _, org := range organizations {
		added, err := EnsureDefaultProject(org.Name)
		if err != nil {
			return created, fmt.Errorf("backfill default project for org %q: %w", org.Name, err)
		}
		if added {
			created++
		}
	}

	if created > 0 {
		fmt.Printf("[backfill-default-project] created=%d\n", created)
	}
	return created, nil
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

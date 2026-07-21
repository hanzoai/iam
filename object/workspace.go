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

package object

import (
	"fmt"

	"github.com/hanzoai/iam-v1/util"
)

// Workspace is the FIRST-CLASS level between an Organization and its Projects:
// Organization → Workspace → Project. It is the identity anchor for a unit of
// work — the thing an org has one-or-many of, that members belong to, and that
// a Project scopes under. It is NOT storage: the physical data plane (S3 bucket,
// git mounts, collab docs) is derived from (Organization, Workspace) by the
// storage layer, so a Workspace here carries only the identity/scoping facts and
// the Bucket handle the storage layer keys on — never a second copy of the data.
//
// Membership is IAM-native (the Membership object), scoped by this Workspace's id
// so a human or bot belongs to a workspace exactly the way it belongs to an org —
// one and only one membership authority. Invitations (the Invitation object) name
// a Workspace to grant a human access; no app maintains its own member table.
type Workspace struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	DisplayName  string   `xorm:"varchar(100)" json:"displayName"`
	Description  string   `xorm:"varchar(500)" json:"description"`
	Organization string   `xorm:"varchar(100) index" json:"organization"`
	// Bucket is the storage layer's handle for this workspace's S3 bucket. Empty
	// means "derive it" (org+workspace); a set value pins an existing bucket. The
	// storage subsystem owns the physical name — IAM only records the binding.
	Bucket   string   `xorm:"varchar(200)" json:"bucket"`
	Tags     []string `xorm:"mediumtext" json:"tags"`
	Metadata string   `xorm:"mediumtext" json:"metadata"`
	// IsDefault marks the org's default workspace — the one a member lands in when
	// none is named, mirroring Project.IsDefault. An org has at most one.
	IsDefault bool `json:"isDefault"`
}

func GetWorkspaceCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Workspace{Owner: owner})
}

func GetWorkspaces(owner string) ([]*Workspace, error) {
	workspaces := []*Workspace{}
	err := ormer.Engine.Desc("created_time").Find(&workspaces, &Workspace{Owner: owner})
	if err != nil {
		return nil, err
	}
	return workspaces, nil
}

func GetPaginationWorkspaces(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Workspace, error) {
	workspaces := []*Workspace{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&workspaces, &Workspace{Owner: owner})
	if err != nil {
		return nil, err
	}
	return workspaces, nil
}

// GetOrganizationWorkspaces returns every workspace under an organization,
// newest first — the org → workspace half of the hierarchy read. It queries the
// indexed Organization column, so a foreign org's name returns nothing.
func GetOrganizationWorkspaces(organization string) ([]*Workspace, error) {
	workspaces := []*Workspace{}
	err := ormer.Engine.Desc("created_time").Find(&workspaces, &Workspace{Organization: organization})
	if err != nil {
		return nil, err
	}
	return workspaces, nil
}

// GetDefaultWorkspace returns an organization's default workspace — the row whose
// Organization matches and IsDefault is true — or nil when the org has none. It is
// the workspace a member lands in when none is named (mirrors GetDefaultProject).
func GetDefaultWorkspace(organization string) (*Workspace, error) {
	if organization == "" {
		return nil, nil
	}

	workspace := Workspace{}
	existed, err := ormer.Engine.Where("organization = ?", organization).And("is_default = ?", true).Get(&workspace)
	if err != nil {
		return nil, err
	}

	if existed {
		return &workspace, nil
	}

	return nil, nil
}

func getWorkspace(owner string, name string) (*Workspace, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	workspace := Workspace{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&workspace)
	if err != nil {
		return nil, err
	}

	if existed {
		return &workspace, nil
	}

	return nil, nil
}

func GetWorkspace(id string) (*Workspace, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getWorkspace(owner, name)
}

func AddWorkspace(workspace *Workspace) (bool, error) {
	if workspace.CreatedTime == "" {
		workspace.CreatedTime = util.GetCurrentTime()
	}

	affected, err := ormer.Engine.Insert(workspace)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func UpdateWorkspace(id string, workspace *Workspace) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}

	existing, err := getWorkspace(owner, name)
	if err != nil {
		return false, err
	}
	if existing == nil {
		return false, nil
	}

	affected, err := ormer.Engine.ID(PK{owner, name}).AllCols().Update(workspace)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteWorkspace(workspace *Workspace) (bool, error) {
	affected, err := ormer.Engine.ID(PK{workspace.Owner, workspace.Name}).Delete(&Workspace{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (workspace *Workspace) GetId() string {
	return fmt.Sprintf("%s/%s", workspace.Owner, workspace.Name)
}

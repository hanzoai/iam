// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package feature_test

import (
	"context"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/feature"
	"github.com/hanzoai/iam2/pkg/model"
)

// A registered feature is mounted by MountAll and reaches the app + store; a
// module that fails to mount surfaces the error (fail-fast).
type fakeFeature struct {
	name    string
	mounted bool
	err     error
}

func (f *fakeFeature) Name() string { return f.name }
func (f *fakeFeature) Mount(app *zip.App, store feature.Store) error {
	f.mounted = true
	return f.err
}

type nopStore struct{}

func (nopStore) GetUser(context.Context, string, string) (*model.User, error) { return nil, nil }
func (nopStore) GetUserByID(context.Context, string) (*model.User, error)     { return nil, nil }
func (nopStore) GetGlobalUsers(context.Context, int, int) ([]*model.User, int, error) {
	return nil, 0, nil
}
func (nopStore) AddUser(context.Context, *model.User) (bool, error)                 { return true, nil }
func (nopStore) UpdateUser(context.Context, *model.User) (bool, error)              { return true, nil }
func (nopStore) DeleteUser(context.Context, string, string) (bool, error)           { return true, nil }
func (nopStore) GetApplication(context.Context, string) (*model.Application, error) { return nil, nil }
func (nopStore) GetOrganization(context.Context, string) (*model.Organization, error) {
	return nil, nil
}
func (nopStore) GetCert(context.Context, string, string) (*model.Cert, error) { return nil, nil }
func (nopStore) SetPassword(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (nopStore) VerifyPassword(context.Context, string, string, string) (bool, error) {
	return true, nil
}

func TestMountAll_MountsRegistered(t *testing.T) {
	f := &fakeFeature{name: "fake"}
	feature.Register(f)
	app := zip.New(zip.Config{DisableStartupMessage: true})
	if err := feature.MountAll(app, nopStore{}); err != nil {
		t.Fatalf("MountAll: %v", err)
	}
	if !f.mounted {
		t.Fatal("registered feature was not mounted")
	}
	found := false
	for _, r := range feature.Registered() {
		if r.Name() == "fake" {
			found = true
		}
	}
	if !found {
		t.Fatal("Registered() did not list the feature")
	}
}

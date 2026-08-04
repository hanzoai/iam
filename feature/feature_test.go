// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package feature_test

import (
	"context"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/feature"
	"github.com/hanzoai/iam/pkg/model"
)

// A registered feature is routed by RouteAll and reaches the app + store; a
// module that fails to register surfaces the error (fail-fast).
type fakeFeature struct {
	name       string
	registered bool
	err        error
}

func (f *fakeFeature) Name() string { return f.name }
func (f *fakeFeature) Route(app *zip.App, store feature.Store) error {
	f.registered = true
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
func (nopStore) GetProvider(context.Context, string, string) (*model.Provider, error) {
	return nil, nil
}
func (nopStore) SetPassword(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (nopStore) VerifyPassword(context.Context, string, string, string) (bool, error) {
	return true, nil
}

func TestRouteAll_RegistersEveryFeature(t *testing.T) {
	f := &fakeFeature{name: "fake"}
	feature.Register(f)
	app := zip.New(zip.Config{DisableStartupMessage: true})
	if err := feature.RouteAll(app, nopStore{}); err != nil {
		t.Fatalf("RouteAll: %v", err)
	}
	if !f.registered {
		t.Fatal("registered feature never had Route called")
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

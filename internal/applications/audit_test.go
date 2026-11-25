// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

func TestApplications_LifecycleAndSecretRotationAudit(t *testing.T) {
	db := memDB(t)
	ctx := principal.Bind(
		zip.WithCaller(context.Background(), zip.Caller{IP: "198.51.100.7"}),
		&policy.Principal{Org: "admin", User: "root", Sudo: true},
	)

	// 1. Create writes application-create audit record.
	if _, err := Create(db)(ctx, &schema.Application{
		Owner:        "admin",
		Name:         "audit-app",
		ClientId:     "audit-app",
		ClientSecret: "initial-secret",
		Organization: "hanzo",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// 2. Masked round-trip update (empty ClientSecret) preserves secret and does NOT emit secret-rotate audit.
	if _, err := Update(db)(ctx, &schema.Application{
		Owner:        "admin",
		Name:         "audit-app",
		ClientId:     "audit-app",
		ClientSecret: "",
		Organization: "hanzo",
		DisplayName:  "Renamed",
	}); err != nil {
		t.Fatalf("update masked round-trip: %v", err)
	}

	// 3. Explicit new secret emits application-secret-rotate audit.
	if _, err := Update(db)(ctx, &schema.Application{
		Owner:        "admin",
		Name:         "audit-app",
		ClientId:     "audit-app",
		ClientSecret: "rotated-secret",
		Organization: "hanzo",
	}); err != nil {
		t.Fatalf("update rotate: %v", err)
	}

	// 4. Delete emits application-delete audit.
	if _, err := deleteApplication(db)(ctx, &ApplicationRef{Owner: "admin", Name: "audit-app"}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// 5. #51 reserved-org confinement refusal must fail closed and emit NO create audit record.
	if _, err := Create(db)(ctx, &schema.Application{
		Owner:        "admin",
		Name:         "unconfined-admin-app",
		ClientId:     "unconfined-admin-app",
		Organization: "admin",
		IsShared:     true,
	}); err == nil {
		t.Fatal("expected unconfined reserved-org app creation to fail")
	}

	logs, err := orm.TypedQuery[schema.AuditLog](db).Filter("Owner=", "admin").GetAll(ctx)
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}

	counts := map[string]int{}
	for _, l := range logs {
		counts[l.Action+":"+l.Object]++
		if l.Object == "audit-app" {
			if l.User != "admin/root" {
				t.Errorf("%s: User = %q, want admin/root", l.Action, l.User)
			}
			if l.ClientIp != "198.51.100.7" {
				t.Errorf("%s: ClientIp = %q, want 198.51.100.7", l.Action, l.ClientIp)
			}
		}
	}
	if counts[schema.ActionApplicationCreate+":audit-app"] != 1 {
		t.Errorf("application-create count = %d, want 1", counts[schema.ActionApplicationCreate+":audit-app"])
	}
	if counts[schema.ActionApplicationSecretRotate+":audit-app"] != 1 {
		t.Errorf("application-secret-rotate count = %d, want 1 (masked round-trip must not log rotation)", counts[schema.ActionApplicationSecretRotate+":audit-app"])
	}
	if counts[schema.ActionApplicationDelete+":audit-app"] != 1 {
		t.Errorf("application-delete count = %d, want 1", counts[schema.ActionApplicationDelete+":audit-app"])
	}
	if counts[schema.ActionApplicationCreate+":unconfined-admin-app"] != 0 {
		t.Errorf("refused unconfined app unexpectedly logged create audit")
	}
}

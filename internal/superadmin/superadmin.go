// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package superadmin appoints and dismisses SuperAdmins (HIP-0527 §3 Appoint a
// SuperAdmin, R2). An appointment creates a NEW account admin/<name> for a named
// person; it never moves or promotes an existing account. The actor is a
// SuperAdmin person who signed in, in person, within StepUp — a credential minted
// for them by anyone else does not qualify. Each act and its fact are one write:
// the account row and a platform-written audit row in one transaction, on a store
// whose transactions are real.
//
// The account is created holding no credential and no org role: no password, no
// key, no membership, no admin flag (R1). Its address is the target's proven
// address, so the person sets a password by a code mailed there and nobody else
// can.
package superadmin

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Path is the SuperAdmin collection: POST appoints, DELETE /:name dismisses.
const Path = "/v1/iam/superadmins"

// StepUp bounds how long ago the actor must have signed in.
const StepUp = 10 * time.Minute

// person is the class a SuperAdmin account carries. A row with no class is not
// counted as one here, whatever the older predicate says of it.
const person = "normal-user"

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the appointment surface on the guarded group.
func Route(app *zip.Group, db orm.DB) {
	app.Post(Path, grantSuperAdmin(db),
		zip.WithOperationID("grantSuperAdmin"),
		zip.WithStatus(201, 400, 401, 403, 404, 409, 503),
		zip.WithTags("superadmins"))
	app.Delete(Path+"/:name", revokeSuperAdmin(db),
		zip.WithOperationID("revokeSuperAdmin"),
		zip.WithStatus(204, 401, 403, 404, 409, 503),
		zip.WithTags("superadmins"))
}

// Target names the person a SuperAdmin account is made for, by the natural key
// of the account they sign in with today.
type Target struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name" validate:"required"`
}

// GrantInput appoints a SuperAdmin.
type GrantInput struct {
	// Target is the person the account is for.
	Target Target `json:"target"`
	// Name is the new account's username in the admin directory. Empty takes the
	// target's own username.
	Name string `json:"name,omitempty"`
	Auth string `json:"-" header:"Authorization"`
}

// AuthzTarget is the account the appointment writes: admin/<name>.
func (in *GrantInput) AuthzTarget() (owner, name string) {
	if in.Name != "" {
		return policy.AdminOrg, in.Name
	}
	return policy.AdminOrg, in.Target.Name
}

// RevokeInput dismisses the SuperAdmin admin/<name>.
type RevokeInput struct {
	Name string `json:"name" validate:"required"`
	Auth string `json:"-" header:"Authorization"`
}

// AuthzTarget is the account the dismissal removes: admin/<name>.
func (in *RevokeInput) AuthzTarget() (owner, name string) { return policy.AdminOrg, in.Name }

// Appointed reports the account an appointment created and the person it is for.
type Appointed struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	// Id is the new account's subject.
	Id string `json:"id"`
	// Person is the account of the person appointed, "<owner>/<name>".
	Person string `json:"person"`
	// Address is where the appointed person's recovery code goes.
	Address string `json:"address"`
}

// StatusCode is 201: an appointment creates an account.
func (*Appointed) StatusCode() int { return 201 }

// Dismissed is the empty answer of a dismissal.
type Dismissed struct{}

// StatusCode is 204.
func (*Dismissed) StatusCode() int { return 204 }

// grantSuperAdmin appoints a SuperAdmin for a named person.
//
// It creates a new account in the admin directory for the person who signs in as
// target today, and records the appointment on the platform trail in the same
// write. It never moves or promotes an account: target keeps everything it had,
// and the new account holds no password, key, org role or admin flag. It takes
// the target's proven address, so the person sets a password by the code mailed
// there; the answer names the person and that address.
//
// Only a SuperAdmin appoints, presenting the access token of their own sign-in
// from the last ten minutes. A target in the admin directory, a machine, a
// suspended account, one without a proven address, a person who already holds a
// SuperAdmin account, or a name an application of the admin directory holds is
// refused.
func grantSuperAdmin(db orm.DB) zip.TypedHandler[GrantInput, Appointed] {
	return func(ctx context.Context, in *GrantInput) (*Appointed, error) {
		actor, client, err := present(ctx, db, in.Auth)
		if err != nil {
			return nil, err
		}
		u, t, err := appoint(ctx, db, actor, client, in.Target, in.Name)
		if err != nil {
			return nil, err
		}
		return &Appointed{Owner: u.Owner, Name: u.Name, Id: u.Id, Person: t.Owner + "/" + t.Name, Address: u.Email}, nil
	}
}

// revokeSuperAdmin dismisses a SuperAdmin.
//
// The account admin/<name> is removed with its memberships, and the dismissal is
// recorded on the platform trail in the same write; its sessions stop at the next
// request that reads the account. The person's own account is untouched. Only a
// SuperAdmin dismisses, presenting the access token of their own sign-in from the
// last ten minutes, and the last SuperAdmin is not dismissed.
func revokeSuperAdmin(db orm.DB) zip.TypedHandler[RevokeInput, Dismissed] {
	return func(ctx context.Context, in *RevokeInput) (*Dismissed, error) {
		actor, client, err := present(ctx, db, in.Auth)
		if err != nil {
			return nil, err
		}
		if err := dismiss(ctx, db, actor, client, in.Name); err != nil {
			return nil, err
		}
		return &Dismissed{}, nil
	}
}

// present is the actor of a request: a SuperAdmin person, never an application,
// whose bearer is the access token of their own recent sign-in. It answers the
// actor as "<owner>/<name>" and the client they signed in through.
func present(ctx context.Context, db orm.DB, auth string) (string, string, error) {
	p, ok := principal.From(ctx)
	if !ok || p == nil || !p.Sudo || p.App != nil || p.User == "" {
		return "", "", zip.ErrForbidden("only a SuperAdmin appoints or dismisses a SuperAdmin")
	}
	u, claims, err := oidc.SignedIn(ctx, db, httpx.BearerValue(auth), StepUp)
	switch {
	case errors.Is(err, oidc.ErrNotSignedIn):
		return "", "", zip.ErrUnauthorized("sign in again, in person, to appoint or dismiss a SuperAdmin")
	case err != nil:
		return "", "", internal(err)
	case u.Owner != p.Org || u.Name != p.User:
		return "", "", zip.ErrForbidden("only a SuperAdmin appoints or dismisses a SuperAdmin")
	}
	return p.Org + "/" + p.User, claims.Azp, nil
}

// appoint is the one operation that creates an account in the admin directory.
func appoint(ctx context.Context, db orm.DB, actor, client string, target Target, name string) (*schema.User, *schema.User, error) {
	if name == "" {
		name = target.Name
	}
	name, err := schema.Username(name)
	if err != nil {
		return nil, nil, zip.ErrBadRequest(err.Error())
	}
	if !store.Atomic(db) {
		return nil, nil, zip.Errorf(503, "appointing a SuperAdmin needs a store with transactions")
	}
	var made, t *schema.User
	err = db.RunInTransaction(ctx, func(tx orm.DB) error {
		if err := standing(ctx, tx, actor); err != nil {
			return err
		}
		var err error
		t, err = store.GetUserByName(ctx, tx, target.Owner, target.Name)
		switch {
		case err != nil:
			return err
		case t == nil:
			return zip.ErrNotFound("no account " + target.Owner + "/" + target.Name)
		case t.Owner == policy.AdminOrg:
			return zip.ErrBadRequest("the target already lives in the admin directory; an appointment never moves or promotes an account")
		case t.Machine():
			return zip.ErrBadRequest("a SuperAdmin is a person, and the target is a machine")
		case t.IsForbidden || t.IsDeleted:
			return zip.ErrBadRequest("the target account is suspended")
		case !t.EmailVerified || store.NormalizeEmail(t.Email) == "":
			return zip.ErrBadRequest("the target has no proven address to recover the account through")
		}
		if held, err := store.GetUserByName(ctx, tx, policy.AdminOrg, name); err != nil {
			return err
		} else if held != nil {
			return zip.ErrConflict("admin/" + name + " exists")
		}
		// A client's machine token names admin/<its application>, and a subject is
		// resolved to a person before an application — so an account of that name
		// would answer to the client's tokens.
		if app, err := store.GetApplicationByName(ctx, tx, policy.AdminOrg, name); err != nil {
			return err
		} else if app != nil {
			return zip.ErrConflict("an application of the admin directory is named " + name)
		}
		switch held, err := store.GetUserByEmail(ctx, tx, policy.AdminOrg, t.Email); {
		case errors.Is(err, store.ErrEmailAmbiguous), err == nil && held != nil:
			return zip.ErrConflict("the target's address already names an account in the admin directory")
		case err != nil:
			return err
		}
		u := newAdmin(tx, t, name)
		if existing, err := store.GetUserById(ctx, tx, u.Id); err != nil {
			return err
		} else if existing != nil {
			return zip.ErrConflict("subject collision; retry")
		}
		if err := u.CreateCtx(ctx); err != nil {
			return err
		}
		made = u
		return store.Append(ctx, tx, fact(schema.ActionSuperAdminAppoint, actor, map[string]string{
			"account": u.Owner + "/" + u.Name, "sub": u.Id,
			"person": t.Owner + "/" + t.Name, "personSub": t.Id,
			"client": client,
		}, Path, 201))
	})
	if err != nil {
		return nil, nil, answer(err)
	}
	return made.Mask(), t, nil
}

// newAdmin builds the account an appointment creates. It is the only code in IAM
// that files an account under the admin directory, and appoint is its one caller
// (HIP-0527 R2).
func newAdmin(tx orm.DB, who *schema.User, name string) *schema.User {
	u := orm.New[schema.User](tx)
	model := u.Model
	now := time.Now().UTC().Format(time.RFC3339)
	u.Owner = policy.AdminOrg
	u.Name = name
	u.Id = uuid.NewString()
	u.Type = person
	u.DisplayName = who.DisplayName
	u.Email = store.NormalizeEmail(who.Email)
	u.EmailVerified = true
	u.CreatedTime, u.UpdatedTime = now, now
	u.Model = model
	u.SetId(policy.AdminOrg + "/" + name)
	return u
}

// dismiss removes admin/<name> and records the dismissal in one write.
func dismiss(ctx context.Context, db orm.DB, actor, client, name string) error {
	if !store.Atomic(db) {
		return zip.Errorf(503, "dismissing a SuperAdmin needs a store with transactions")
	}
	err := db.RunInTransaction(ctx, func(tx orm.DB) error {
		if err := standing(ctx, tx, actor); err != nil {
			return err
		}
		u, err := store.GetUserByName(ctx, tx, policy.AdminOrg, name)
		switch {
		case err != nil:
			return err
		case u == nil || !u.SuperAdmin():
			return zip.ErrNotFound("no SuperAdmin admin/" + name)
		}
		if live(u) {
			n, err := superadmins(ctx, tx)
			if err != nil {
				return err
			}
			if n <= 1 {
				return zip.ErrConflict("the last SuperAdmin is not dismissed")
			}
		}
		key := u.Owner + "/" + u.Name
		if _, err := store.ForgetUser(ctx, tx, key); err != nil {
			return err
		}
		if err := u.DeleteCtx(ctx); err != nil {
			return err
		}
		return store.Append(ctx, tx, fact(schema.ActionSuperAdminDismiss, actor, map[string]string{
			"account": key, "sub": u.Id, "client": client,
		}, Path+"/"+u.Name, 204))
	})
	return answer(err)
}

// standing holds the actor to I18 at the moment of the write: a live SuperAdmin
// person of the admin directory, read from its row.
func standing(ctx context.Context, tx orm.DB, actor string) error {
	owner, name, _ := strings.Cut(actor, "/")
	if owner != policy.AdminOrg || name == "" {
		return zip.ErrForbidden("only a SuperAdmin appoints or dismisses a SuperAdmin")
	}
	u, err := store.GetUserByName(ctx, tx, owner, name)
	if err != nil {
		return err
	}
	if u == nil || !live(u) {
		return zip.ErrForbidden("only a SuperAdmin appoints or dismisses a SuperAdmin")
	}
	return nil
}

// live reports whether u is a SuperAdmin this package counts: a person of the
// admin directory who says so by class, and is neither suspended nor deleted.
func live(u *schema.User) bool {
	return u.SuperAdmin() && u.Type == person && !u.IsForbidden && !u.IsDeleted
}

// superadmins counts the live SuperAdmins in the admin directory.
func superadmins(ctx context.Context, tx orm.DB) (int, error) {
	us, err := orm.TypedQuery[schema.User](tx).Filter("Owner=", policy.AdminOrg).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return 0, err
	}
	n := 0
	for _, u := range us {
		if live(u) {
			n++
		}
	}
	return n, nil
}

// fact is the platform-written audit row an appointment or a dismissal leaves,
// filed on the SuperAdmin trail.
func fact(action, actor string, object map[string]string, uri string, status int) *schema.AuditLog {
	body, _ := json.Marshal(object)
	return &schema.AuditLog{
		Owner:      policy.AdminOrg,
		User:       actor,
		Action:     action,
		Object:     string(body),
		Method:     map[int]string{201: "POST", 204: "DELETE"}[status],
		RequestUri: uri,
		StatusCode: status,
	}
}

// answer passes a refusal through and hides a store failure's detail.
func answer(err error) error {
	if err == nil {
		return nil
	}
	var he *zip.HTTPError
	if errors.As(err, &he) {
		return err
	}
	return internal(err)
}

func internal(err error) error {
	log.Printf("superadmin: %v", err)
	return zip.ErrInternal("server_error")
}

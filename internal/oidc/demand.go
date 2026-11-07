// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// What an authorize request DEMANDED, kept by the server.
//
// Authorize hands a request it will not answer from a session to the hosted page:
// `prompt=login` (prove it again), `prompt=select_account` (the person chooses),
// `max_age` (a sign-in no older than this). The page may then resume from the
// session with a credential-less POST to the login endpoint, and that post carries
// only what the page chose to forward. A page that forwarded nothing used to get a
// code from the old session — hanzo.ai's resume for the CLI dropped
// `prompt=select_account` and `prompt=login` alike, so both completed silently.
//
// So the demand is recorded where the request was validated and read where a
// session would answer it: a LoginChallenge row of kind `prompt`, named by the
// request's own identity (client, redirect, state, PKCE challenge), which the page
// must carry back unchanged for the code to be any use to the client. A page that
// alters any of them gets a code bound to a request the client never made. The
// row lives as long as a sign-in screen reasonably stays open and is never
// consumed: every resume of the same request reads the same demand.

// KindPrompt is the LoginChallenge kind of a recorded demand.
const KindPrompt = "prompt"

// demandTTL bounds how long a demand outlives its authorize request.
const demandTTL = 30 * time.Minute

// demand is what one authorize request asked of a sign-in.
type demand struct {
	Login  bool   `json:"login,omitempty"`  // prompt=login: a credential proven after the request
	Choose bool   `json:"choose,omitempty"` // prompt=select_account, or several accounts and none named
	MaxAge string `json:"maxAge,omitempty"` // max_age as the client sent it
	Since  int64  `json:"since,omitempty"`  // when the request was made, unix seconds
}

// needed reports whether d asks anything a session could fail to give.
func (d demand) needed() bool { return d.Login || d.Choose || d.MaxAge != "" }

// met reports whether a session authenticated at authTime answers d, for a
// request that named its account (hinted) or did not. prompt=login is met by a
// sign-in made after the request's second, which is what a person finishing the page's
// form produces; select_account by an account the person named; max_age by a
// sign-in that recent.
func (d demand) met(authTime int64, hinted bool) bool {
	if d.Login && authTime <= d.Since {
		return false
	}
	if d.Choose && !hinted {
		return false
	}
	return freshEnough(authTime, d.MaxAge)
}

// demandKey names the request: the four values its code is bound to.
func demandKey(clientID, redirectURI, state, challenge string) string {
	h := sha256.Sum256([]byte(clientID + "\x00" + redirectURI + "\x00" + state + "\x00" + challenge))
	return "prompt-" + hex.EncodeToString(h[:])
}

// rememberDemand records d for the request, replacing an earlier record of it.
func rememberDemand(ctx context.Context, db orm.DB, key string, d demand) error {
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	now := nowFunc()
	id := challengeOwner + "/" + key
	row, err := orm.Get[schema.LoginChallenge](db, id)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	if row != nil {
		row.Kind, row.Payload, row.Used = KindPrompt, string(payload), false
		row.ExpireIn = now.Add(demandTTL).Unix()
		return row.UpdateCtx(ctx)
	}
	c := orm.New[schema.LoginChallenge](db)
	c.Owner, c.Name = challengeOwner, key
	c.CreatedTime = now.UTC().Format(time.RFC3339)
	c.Kind, c.Payload = KindPrompt, string(payload)
	c.ExpireIn = now.Add(demandTTL).Unix()
	c.SetId(id)
	return c.CreateCtx(ctx)
}

// demandOf is what the request named by key demanded: the zero demand when it
// recorded none or the record has expired, and an error when the store could not
// say, which the caller answers by refusing rather than by guessing "none".
func demandOf(db orm.DB, key string) (demand, error) {
	row, err := orm.Get[schema.LoginChallenge](db, challengeOwner+"/"+key)
	if errors.Is(err, orm.ErrNotFound) {
		return demand{}, nil
	}
	if err != nil {
		return demand{}, err
	}
	if row == nil || row.Kind != KindPrompt || nowFunc().Unix() > row.ExpireIn {
		return demand{}, nil
	}
	var d demand
	if err := json.Unmarshal([]byte(row.Payload), &d); err != nil {
		return demand{}, err
	}
	return d, nil
}

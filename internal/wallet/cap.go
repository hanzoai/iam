// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Cap bounds the accounts wallet sign-up CREATES for one client address (IP)
// and for one network (Subnet: an IPv4 /24, an IPv6 /64) in a Window. A wallet
// is a key anyone can generate for free, so without it one script mints
// accounts without end. Only creations count: a wallet already on file signs
// its holder in untouched, and so does linking a wallet to an account already
// held. A zero IP or Subnet is that bound off.
//
// An IPv6 client can move inside its /64 at will, so there Subnet is the bound
// that holds.
type Cap struct {
	IP     int
	Subnet int
	Window time.Duration
}

// DefaultCap is the bound a deployment holds to unless it names its own.
var DefaultCap = Cap{IP: 10, Subnet: 50, Window: 24 * time.Hour}

// The variables a deployment names its own Cap in. Unset keeps DefaultCap's
// value and "0" turns that bound off. A value that does not read keeps the
// default and is logged, so a typo never lifts the bound.
const (
	EnvCapIP     = "IAM_WALLET_CAP_IP"
	EnvCapSubnet = "IAM_WALLET_CAP_SUBNET"
	EnvCapWindow = "IAM_WALLET_CAP_WINDOW" // a Go duration: 24h, 90m
)

// CodeCapped is the stable reason a creation the Cap refused carries.
const CodeCapped = "wallet_signup_capped"

// capFrom reads the Cap from env. A value it cannot read keeps its default and
// is named in the error.
func capFrom(env func(string) string) (Cap, error) {
	c := DefaultCap
	var bad []string
	count := func(name string, dst *int) {
		raw := strings.TrimSpace(env(name))
		if raw == "" {
			return
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			bad = append(bad, name+"="+strconv.Quote(raw))
			return
		}
		*dst = n
	}
	count(EnvCapIP, &c.IP)
	count(EnvCapSubnet, &c.Subnet)
	if raw := strings.TrimSpace(env(EnvCapWindow)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			bad = append(bad, EnvCapWindow+"="+strconv.Quote(raw))
		} else {
			c.Window = d
		}
	}
	if len(bad) > 0 {
		return c, fmt.Errorf("wallet: %s unreadable; the default holds", strings.Join(bad, ", "))
	}
	return c, nil
}

// counted is the client's address and its network as the ledger files them. The
// zero client files both as "", which every such request shares.
func counted(ip netip.Addr) (addr, network string) {
	if !ip.IsValid() {
		return "", ""
	}
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits) // a valid address holds a /24 or a /64
	return ip.String(), p.String()
}

// capped is a creation the Cap refused: the bound that held it, and how long
// until that bound admits one more.
type capped struct {
	bound  string // "ip" | "subnet"
	limit  int
	window time.Duration
	retry  time.Duration
}

func (e *capped) Error() string {
	if e.bound == "ip" {
		return "web3: too many new accounts from this address; try again later"
	}
	return "web3: too many new accounts from this network; try again later"
}

// admit returns a *capped when the Cap holds this creation, else nil. It counts
// the ledger (schema.ActionWalletSignup) inside the transaction that writes the
// account and its ledger row, so concurrent creations cannot all pass one
// count: SQLite serializes writers and the SQL store runs serializable.
func admit(ctx context.Context, tx orm.DB, c Cap, ip netip.Addr, now time.Time) error {
	addr, network := counted(ip)
	since := now.Add(-c.Window)
	for _, b := range []struct {
		bound, field, key string
		limit             int
	}{
		{"ip", "ClientIp", addr, c.IP},
		{"subnet", "Object", network, c.Subnet},
	} {
		if b.limit <= 0 {
			continue
		}
		n, err := store.Recorded(ctx, tx, schema.ActionWalletSignup, since, b.field, b.key)
		if err != nil {
			return err
		}
		if n < b.limit {
			continue
		}
		// One more is admitted once the window drops the row that leaves fewer
		// than limit: the (n-limit)th oldest.
		row, err := orm.TypedQuery[schema.AuditLog](tx).
			Filter("Action=", schema.ActionWalletSignup).
			Filter("CreatedTime>=", since.UTC().Format(time.RFC3339)).
			Filter(b.field+"=", b.key).
			Order("CreatedTime").
			Offset(n - b.limit).
			First()
		if err != nil {
			return err
		}
		at, err := time.Parse(time.RFC3339, row.CreatedTime)
		if err != nil {
			return err
		}
		// The stamp is to the second, so the row is up to a second younger.
		return &capped{bound: b.bound, limit: b.limit, window: c.Window, retry: at.Add(c.Window + time.Second).Sub(now)}
	}
	return nil
}

// file records that this request created user, in the ledger admit counts:
// under the application's org, with the client address and its network.
func file(ctx context.Context, tx orm.DB, in login, user *schema.User) error {
	addr, network := counted(in.Client)
	return store.Append(ctx, tx, &schema.AuditLog{
		Owner:        in.App.Organization,
		Organization: in.App.Organization,
		User:         user.Owner + "/" + user.Name,
		ClientIp:     addr,
		Object:       network,
		Action:       schema.ActionWalletSignup,
		Method:       http.MethodPost,
		RequestUri:   PathVerify,
		StatusCode:   http.StatusOK,
	})
}

// held is what a refused creation's envelope carries in data: the bound that
// held it ("ip" or "subnet"), its limit, its window and the wait, in seconds.
type held struct {
	Cap        string `json:"cap"`
	Limit      int    `json:"limit"`
	Window     int64  `json:"window"`
	RetryAfter int64  `json:"retryAfter"`
}

// refuse answers a creation the Cap held: 429 with Retry-After, the stable
// code, and the bound in data.
func refuse(c *zip.Ctx, e *capped) error {
	retry := int64(math.Ceil(e.retry.Seconds()))
	if retry < 1 {
		retry = 1
	}
	c.SetHeader("Retry-After", strconv.FormatInt(retry, 10))
	a := httpx.Bad(http.StatusTooManyRequests, e.Error(), CodeCapped)
	a.Data = held{Cap: e.bound, Limit: e.limit, Window: int64(e.window / time.Second), RetryAfter: retry}
	return c.JSON(a.StatusCode(), a.Response)
}

// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
)

// What an unauthenticated stranger may ask of the device grant, and what it costs
// to be wrong. Starting a device authorization needs no credential (a public CLI has
// none), so the start is the one door a flood can come through, and the user_code it
// mints is a 40-bit secret a signed-in person can be guessing at.

const (
	// deviceScopeLimit bounds the scope a start may name, as authorize bounds its own
	// (paramLimits): a request past it is refused, not cut.
	deviceScopeLimit = 2048
	// deviceStartsPerClient and deviceStartsPerAddress are how many authorizations one
	// client, and one address, may start in a minute. A person starts one when they
	// type `hanzo login`; a CLI fleet behind one address is a handful.
	deviceStartsPerClient  = 120
	deviceStartsPerAddress = 30
	// deviceMissesPerAccount is how many codes one signed-in account may get wrong in
	// deviceMissWindow before every answer to it is the same refusal: 40 bits over a
	// ten-minute life is out of reach for a person, and a miss is a guess.
	deviceMissesPerAccount = 10
	deviceMissWindow       = 15 * time.Minute
	// devicePurgeBatch is how many dead authorizations one start sweeps away.
	devicePurgeBatch = 50
)

// standardScopes are the OpenID Connect scopes IAM advertises (Discovery). A device
// application that declares scopes of its own is held to those; one that declares
// none is held to these. Anything else the requester names is dropped: the person
// approving is shown what the device may do, and what the device asked for is not
// that.
var standardScopes = []string{"openid", "profile", "email", "address", "phone", "offline_access"}

// grantedScope is the scope a device authorization carries: what the requester asked
// for, intersected with what the application may have. `openid` is always allowed.
// The result is the grant's, in the order asked, without repeats.
func grantedScope(app *schema.Application, asked string) []string {
	allowed := map[string]bool{"openid": true}
	if app != nil && len(app.Scopes) > 0 {
		for _, s := range app.Scopes {
			if s != nil && strings.TrimSpace(s.Name) != "" {
				allowed[strings.TrimSpace(s.Name)] = true
			}
		}
	} else {
		for _, s := range standardScopes {
			allowed[s] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range strings.Fields(asked) {
		if allowed[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// guessCount is a fixed-window counter.
type guessCount struct {
	n     int
	until time.Time
}

// budget counts events per key in a window. It is a value of this process, so a
// fleet of replicas allows a replica's share each: a brake on a flood and on
// guessing, never an exact meter. Bounded, because the attacker picks the keys.
type budget struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	seen   map[string]*guessCount
}

func newBudget(window time.Duration, limit int) *budget {
	return &budget{window: window, limit: limit, seen: map[string]*guessCount{}}
}

const budgetKeys = 8192

func (b *budget) get(key string, now time.Time) *guessCount {
	t := b.seen[key]
	if t == nil || now.After(t.until) {
		if len(b.seen) >= budgetKeys {
			for k, v := range b.seen {
				if now.After(v.until) {
					delete(b.seen, k)
				}
			}
			if len(b.seen) >= budgetKeys {
				b.seen = map[string]*guessCount{}
			}
		}
		t = &guessCount{until: now.Add(b.window)}
		b.seen[key] = t
	}
	return t
}

// spend counts one event under key and reports how many the window now holds.
func (b *budget) spend(key string, now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.get(key, now)
	t.n++
	return t.n
}

// within counts one event under key and reports whether it was inside the limit.
func (b *budget) within(key string, now time.Time) bool { return b.spend(key, now) <= b.limit }

// left is how long key's window has to run, for a Retry-After: zero when key holds
// no window that is still open.
func (b *budget) left(key string, now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.seen[key]
	if t == nil || now.After(t.until) {
		return 0
	}
	return t.until.Sub(now)
}

// spent reports whether key is already over its limit, counting nothing.
func (b *budget) spent(key string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.seen[key]
	return t != nil && !now.After(t.until) && t.n >= b.limit
}

var (
	deviceClientStarts  = newBudget(time.Minute, deviceStartsPerClient)
	deviceAddressStarts = newBudget(time.Minute, deviceStartsPerAddress)
	deviceMisses        = newBudget(deviceMissWindow, deviceMissesPerAccount)
)

// resetDeviceBudgets empties every counter, for a test that starts many. The agent
// registration's budgets (agent.go) are emptied with them: both kinds of request
// share the approval page, and a test that starts many of either means all of them.
func resetDeviceBudgets() {
	deviceClientStarts = newBudget(time.Minute, deviceStartsPerClient)
	deviceAddressStarts = newBudget(time.Minute, deviceStartsPerAddress)
	deviceMisses = newBudget(deviceMissWindow, deviceMissesPerAccount)
	agentAddressStarts = newBudget(agentStartWindow, agentStartsPerAddress)
	agentHintStarts = newBudget(agentStartWindow, agentStartsPerHint)
}

// requesterOf is who the edge says is asking: the address it saw connect, and its
// two-letter country for it. The headers are the edge's (CF-Connecting-IP and
// CF-IPCountry); httpx.Client reads no hop a client could have written, and a
// country that is not two capital letters is none.
func requesterOf(c *zip.Ctx) (ip, country string) {
	if a := httpx.Client(c.Header("CF-Connecting-IP"), c.Header("X-Forwarded-For")); a.IsValid() {
		ip = a.String()
	}
	if v := strings.TrimSpace(c.Header("CF-IPCountry")); len(v) == 2 && v[0] >= 'A' && v[0] <= 'Z' && v[1] >= 'A' && v[1] <= 'Z' {
		country = v
	}
	return ip, country
}

// missed counts a wrong code against the account that tried it, and says it once
// when the account has used its budget, as an alarm: someone signed in is guessing.
func missed(subject string, now time.Time) {
	if deviceMisses.spend(subject, now) == deviceMissesPerAccount+1 {
		log.Printf("device: %s has used its %d wrong codes in %s; every answer to it is now a refusal", subject, deviceMissesPerAccount, deviceMissWindow)
	}
}

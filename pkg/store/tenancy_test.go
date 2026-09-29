// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"testing/quick"
)

// The property tests of HIP-0527 §7, part of ADMIN_NAMESPACE_INVARIANTS (§8 R7
// rows 2, 5 and 6). Random operation logs of every kind are applied to the fold;
// after each accepted operation the invariants hold, a role fact moves only the
// pair it names, nothing but an appointment, a dismissal or a move changes
// superadmin, and an assume changes no role.

var (
	people   = []string{"p0", "p1", "p2", "p3", "p4"}
	programs = []string{"m0", "m1"}
	supers   = []string{"s0", "s1", "s2"}
	named    = []string{"acme", "globex", "initech", "admin", "id", "iam"}
	boxes    = []string{"x@acme.test", "y@globex.test"}
	fams     = []string{"f0", "f1"}
	roles    = []string{RoleMember, RoleAdmin, RoleOwner, "root"}
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.Intn(len(xs))] }

// world is every account and org a generated log can name.
func world() (accounts, orgs []string) {
	accounts = slices.Concat(people, programs, supers)
	orgs = slices.Concat(named, []string{"h-p0", "h-p1", "h-p2", "h-p3", "h-p4"})
	return accounts, orgs
}

// plausible draws from what the log already holds most of the time and from the
// whole world otherwise, so that accepted operations of every kind are common and
// refused ones are still exercised.
type plausible struct {
	r  *rand.Rand
	tn *Tenancy
}

func (g plausible) or(xs, all []string) string {
	if len(xs) == 0 || g.r.Intn(5) == 0 {
		return pick(g.r, all)
	}
	return pick(g.r, xs)
}

func (g plausible) orgs() []string {
	var out []string
	for o := range g.tn.orgs {
		out = append(out, o)
	}
	slices.Sort(out)
	return out
}

// holding is every account holding at least role in o.
func (g plausible) holding(o, role string) []string {
	accounts, _ := world()
	var out []string
	for _, a := range accounts {
		if rank[g.tn.Role(a, o)] >= rank[role] {
			out = append(out, a)
		}
	}
	return out
}

func (g plausible) open() []string {
	var out []string
	for _, f := range g.tn.facts {
		if f.Op == OpInvited && !g.tn.used(f.N) {
			out = append(out, f.N)
		}
	}
	return out
}

func (g plausible) sudo() []string {
	var out []string
	for _, a := range supers {
		if g.tn.SuperAdmin(a) {
			out = append(out, a)
		}
	}
	return out
}

// step applies one random operation.
func step(r *rand.Rand, tn *Tenancy, at int64) (string, error) {
	accounts, all := world()
	g := plausible{r, tn}
	o := g.or(g.orgs(), all)
	admins := g.holding(o, RoleAdmin)
	role := g.or(roles[:3], roles)
	ops := []string{"signup", "found", "found", "enroll", "invite", "invite", "invite", "accept", "accept",
		"accept", "assign", "assign", "revoke", "revoke", "revoke", "assume", "release", "switch", "appoint", "dismiss"}
	switch op := pick(r, ops); op {
	case "signup":
		p := pick(r, people)
		return op, tn.Signup(p, "h-"+p, at)
	case "found":
		a := g.or(people, accounts)
		return op, tn.Found(a, pick(r, all), g.or(append(g.sudo(), a, a, a), slices.Concat(accounts, []string{Genesis})), at)
	case "enroll":
		return op, tn.Enroll(pick(r, programs), o, role, g.or(admins, accounts), at)
	case "invite":
		return op, tn.Invite(fmt.Sprintf("n%d", r.Intn(12)), o, pick(r, boxes), role, g.or(admins, accounts), at)
	case "accept":
		return op, tn.Accept(g.or(people, accounts), g.or(g.open(), []string{"n0", "n99"}), at)
	case "assign":
		return op, tn.Assign(g.or(g.holding(o, RoleMember), accounts), o, role, g.or(admins, accounts), at)
	case "revoke":
		a := g.or(g.holding(o, RoleMember), accounts)
		return op, tn.Revoke(a, o, g.or(append(admins, a), accounts), at)
	case "assume":
		return op, tn.Assume(g.or(g.sudo(), accounts), pick(r, fams), o, at)
	case "release":
		return op, tn.Release(g.or(g.sudo(), accounts), pick(r, fams), at)
	case "switch":
		if r.Intn(4) == 0 {
			o = ""
		}
		return op, tn.Switch(pick(r, accounts), o, at)
	case "appoint":
		return op, tn.Appoint(pick(r, supers), pick(r, people), g.or(g.sudo(), slices.Concat(accounts, []string{Genesis})), at)
	default:
		return op, tn.Dismiss(g.or(g.sudo(), supers), g.or(g.sudo(), accounts), at)
	}
}

type snapshot struct {
	roles  map[[2]string]string
	super  map[string]bool
	home   map[string]string
	acting map[[2]string]string
	payer  map[[2]string]string
	orgs   map[string]string
}

func snap(tn *Tenancy) snapshot {
	accounts, orgs := world()
	s := snapshot{
		roles: map[[2]string]string{}, super: map[string]bool{}, home: map[string]string{},
		acting: map[[2]string]string{}, payer: map[[2]string]string{}, orgs: map[string]string{},
	}
	for _, a := range accounts {
		s.super[a] = tn.SuperAdmin(a)
		s.home[a] = tn.Home(a)
		s.orgs[a] = fmt.Sprint(tn.Orgs(a))
		for _, o := range orgs {
			s.roles[[2]string{a, o}] = tn.Role(a, o)
		}
		for _, f := range slices.Concat([]string{""}, fams) {
			s.acting[[2]string{a, f}] = tn.Acting(a, f)
			s.payer[[2]string{a, f}] = tn.Payer(a, f)
		}
	}
	return s
}

// touched is the (account, org) pairs a fact is about, for role facts.
func touched(tn *Tenancy, fs []Fact) map[[2]string]bool {
	out := map[[2]string]bool{}
	for _, f := range fs {
		switch f.Op {
		case OpFounded, OpAssigned, OpRevoked:
			out[[2]string{f.A, f.O}] = true
		case OpAccepted:
			if inv := tn.invitation(f.N); inv != nil {
				out[[2]string{f.A, inv.O}] = true
			}
		}
	}
	return out
}

func TestAdminNamespaceInvariants_foldHoldsOverRandomLogs(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		tn := NewTenancy("acme")
		accepted := 0
		for at := int64(1); at <= 160; at++ {
			before := snap(tn)
			n := len(tn.facts)
			op, err := step(r, tn, at)
			if err != nil {
				if !errors.Is(err, ErrRefused) {
					t.Errorf("seed %d: %s answered %v, not a refusal", seed, op, err)
					return false
				}
				if len(tn.facts) != n {
					t.Errorf("seed %d: a refused %s appended facts", seed, op)
					return false
				}
				continue
			}
			accepted++
			if v := tn.Violations(); len(v) > 0 {
				t.Errorf("seed %d: after %s: %v", seed, op, v)
				return false
			}
			added := tn.facts[n:]
			after := snap(tn)
			pairs := touched(tn, added)
			// I15: a fact about (a, o) leaves role(a, o′) unchanged for every other pair;
			// an assume, a release, a switch and an invitation change no role at all.
			for k, was := range before.roles {
				if !pairs[k] && after.roles[k] != was {
					t.Errorf("seed %d: %s moved role%v from %q to %q", seed, op, k, was, after.roles[k])
					return false
				}
			}
			// I16: no role fact changes superadmin.
			if op != "appoint" && op != "dismiss" && !reflect.DeepEqual(before.super, after.super) {
				t.Errorf("seed %d: %s changed superadmin", seed, op)
				return false
			}
		}
		// Determinism: the fold does not read the order the log was written in.
		shuffled := *tn
		shuffled.facts = slices.Clone(tn.facts)
		r.Shuffle(len(shuffled.facts), func(i, j int) {
			shuffled.facts[i], shuffled.facts[j] = shuffled.facts[j], shuffled.facts[i]
		})
		if !reflect.DeepEqual(snap(tn), snap(&shuffled)) {
			t.Errorf("seed %d: the fold depends on append order", seed)
			return false
		}
		return accepted > 0
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 300}); err != nil {
		t.Fatal(err)
	}
}

// L1: a move changes owner(a) and nothing else — home, orgs, acting and payer are
// what they were, for every account and every token family.
func TestAdminNamespaceInvariants_moveIsInvisible(t *testing.T) {
	prop := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		tn := NewTenancy("acme")
		legacy := []string{"acme", "globex", "hanzo"}
		for _, p := range people {
			if err := tn.Legacy(p, pick(r, legacy), false); err != nil {
				t.Fatal(err)
			}
		}
		for _, m := range programs {
			if err := tn.Legacy(m, pick(r, legacy), true); err != nil {
				t.Fatal(err)
			}
		}
		at := int64(1)
		next := func() int64 { at++; return at }
		if err := tn.Appoint("s0", "p0", Genesis, next()); err != nil {
			t.Fatal(err)
		}
		homed := map[string]bool{}
		for _, p := range people[1:] {
			if r.Intn(5) > 0 {
				if err := tn.FoundHome(p, "h-"+p, pick(r, []string{p, "s0"}), next()); err != nil {
					t.Fatal(err)
				}
				homed[p] = true
			}
		}
		// Named orgs, invitations and programs, then switches and assumes.
		for i := 0; i < 60; i++ {
			switch r.Intn(6) {
			case 0:
				_ = tn.Found(pick(r, people), pick(r, []string{"acme2", "globex2", "initech"}), pick(r, []string{"s0", pick(r, people)}), next())
			case 1:
				n := fmt.Sprintf("n%d", i)
				if tn.Invite(n, pick(r, []string{"acme2", "globex2", "initech"}), pick(r, boxes), pick(r, roles), pick(r, people), next()) == nil {
					_ = tn.Accept(pick(r, people), n, next())
				}
			case 2:
				_ = tn.Enroll(pick(r, programs), pick(r, []string{"acme2", "globex2", "initech"}), RoleMember, pick(r, people), next())
			case 3:
				_ = tn.Switch(pick(r, people), pick(r, []string{"", "acme2", "globex2", "initech"}), next())
			case 4:
				_ = tn.Assume("s0", pick(r, fams), pick(r, []string{"acme2", "globex2", "initech", "h-p1"}), next())
			default:
				_ = tn.Revoke(pick(r, people), pick(r, []string{"acme2", "globex2", "initech"}), pick(r, people), next())
			}
		}
		before := snap(tn)
		for _, a := range slices.Concat(people[1:], programs) {
			if err := tn.Move(a, "", next()); err != nil {
				// A person with its org of one always moves; a program moves once it
				// acts in exactly one org.
				if !errors.Is(err, ErrRefused) || homed[a] {
					t.Errorf("seed %d: move %s: %v", seed, a, err)
					return false
				}
				continue
			}
			if tn.accounts[a].owner != DirID {
				t.Errorf("seed %d: %s did not move", seed, a)
				return false
			}
		}
		after := snap(tn)
		for _, x := range []struct {
			name string
			a, b any
		}{
			{"home", before.home, after.home}, {"orgs", before.orgs, after.orgs},
			{"acting", before.acting, after.acting}, {"payer", before.payer, after.payer},
			{"superadmin", before.super, after.super},
		} {
			if !reflect.DeepEqual(x.a, x.b) {
				t.Errorf("seed %d: a move changed %s:\n before %v\n after  %v", seed, x.name, x.a, x.b)
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}

// The refusals §7 names, each asserted on its own, plus the appointment rules of
// I18.
func TestAdminNamespaceInvariants_refusals(t *testing.T) {
	var at int64
	next := func() int64 { at++; return at }
	tn := NewTenancy("acme")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	refuse := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: want a refusal, got %v", what, err)
		}
	}
	must(tn.Signup("alice", "h-alice", next()))
	must(tn.Signup("bob", "h-bob", next()))
	must(tn.Found("alice", "acme", "alice", next()))

	refuse("a non-member switch", tn.Switch("bob", "acme", next()))
	refuse("an invitation into a personal org", tn.Invite("n1", "h-alice", "b@x.test", RoleMember, "alice", next()))
	refuse("a revoke of the last owner", tn.Revoke("alice", "acme", "alice", next()))
	refuse("a demotion of the last owner", tn.Assign("alice", "acme", RoleAdmin, "alice", next()))
	for _, r := range []string{"admin", "id", "org", "app", "iam"} {
		refuse("founding reserved "+r, tn.Found("alice", r, "alice", next()))
	}
	refuse("a direct grant to a non-member", tn.Assign("bob", "acme", RoleMember, "alice", next()))
	refuse("an invitation above the inviter's role", func() error {
		must(tn.Invite("n2", "acme", "b@x.test", RoleAdmin, "alice", next()))
		must(tn.Accept("bob", "n2", next()))
		return tn.Invite("n3", "acme", "c@x.test", RoleOwner, "bob", next())
	}())
	refuse("a spent invitation", tn.Accept("alice", "n2", next()))

	refuse("an appointment by a person", tn.Appoint("root", "alice", "alice", next()))
	must(tn.Appoint("root", "alice", Genesis, next()))
	refuse("genesis once admin is not empty", tn.Appoint("root2", "bob", Genesis, next()))
	refuse("appointing an admin account", tn.Appoint("root2", "root", "root", next()))
	refuse("a SuperAdmin founding for themself", tn.Found("root", "globex", "root", next()))
	refuse("a SuperAdmin accepting a role", func() error {
		must(tn.Invite("n4", "acme", "r@x.test", RoleMember, "alice", next()))
		return tn.Accept("root", "n4", next())
	}())
	refuse("dismissing the last SuperAdmin", tn.Dismiss("root", "root", next()))
	refuse("an assume by a person", tn.Assume("alice", "f", "acme", next()))
	must(tn.Assume("root", "f", "acme", next()))
	if len(tn.Orgs("root")) != 0 || tn.Member("root", "acme") {
		t.Errorf("an assume granted a role: %v", tn.Orgs("root"))
	}
	if got := tn.Payer("root", "f"); got != "acme" {
		// Support is acme in this log, which makes the payer under assume acme.
		t.Errorf("payer under assume = %q", got)
	}
	if got := tn.Payer("root", ""); got != "" {
		t.Errorf("a SuperAdmin outside an assume pays from %q, want nobody", got)
	}
	refuse("time running backwards", tn.Signup("carol", "h-carol", 1))
	if v := tn.Violations(); len(v) > 0 {
		t.Errorf("violations: %v", v)
	}
}

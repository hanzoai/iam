// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/pkg/schema"
)

// Tenancy is the formal core of HIP-0527 §1: an append-only log of facts and the
// four predicates folded from it — superadmin, role, acting org and payer. Every
// operation validates against the fold as it stands, appends its facts, and never
// rewrites one. Predicates are total functions of the log.
//
// It is the reference the invariant suite (ADMIN_NAMESPACE_INVARIANTS, HIP-0527
// §8 R7) checks by property test, and the fold the migration steps of §5 compute
// memberships, acting orgs and payers from.
type Tenancy struct {
	// Support is the org a SuperAdmin's support work bills: Hanzo Inc's own.
	Support string

	accounts map[string]*tenant
	orgs     map[string]bool // slug → personal
	facts    []Fact
	now      int64
}

type tenant struct {
	program bool
	owner   string // a directory (DirID, DirAdmin) or, before §5 step 10, a legacy org
	created string // owner at creation; I12 compares against it
	gone    bool   // dismissed: the account left the admin directory
}

// Directories an account lives in (HIP-0527 §1 Dir).
const (
	DirID    = "id"
	DirAdmin = policy.AdminOrg
)

// Genesis is the actor of the first appointment, admitted only while the admin
// directory is empty (HIP-0527 I18).
const Genesis = "genesis"

// Fact operations (HIP-0527 §1 Facts).
const (
	OpFounded   = "founded"
	OpInvited   = "invited"
	OpAccepted  = "accepted"
	OpAssigned  = "assigned"
	OpRevoked   = "revoked"
	OpAssumed   = "assumed"
	OpReleased  = "released"
	OpSwitched  = "switched"
	OpAppointed = "appointed"
	OpDismissed = "dismissed"
	OpMoved     = "moved"
)

// Fact is one entry of the log. Which fields an operation fills is fixed by the
// operation: founded(A, O, By), invited(N, O, M, R, By), accepted(A, N),
// assigned(A, O, R, By), revoked(A, O, By), assumed(A, S, O), released(A, S),
// switched(A, O), appointed(A, P, By), dismissed(A, By), moved(A, From).
type Fact struct {
	Op   string
	T    int64
	A    string // the account the fact is about, by sub
	O    string // the org
	N    string // the invitation
	M    string // the mailbox an invitation names
	R    string // the role
	By   string // the actor
	S    string // the token family (assumed, released)
	P    string // the person an appointment is made for
	From string // the owner a moved account left
}

// Reserved reports whether slug is a namespace no one is a member of.
func Reserved(slug string) bool {
	switch slug {
	case policy.AdminOrg, DirID, "org", "app", "iam":
		return true
	}
	return false
}

var rank = map[string]int{RoleMember: 1, RoleAdmin: 2, RoleOwner: 3}

// NewTenancy is an empty log whose support work bills the org named support.
func NewTenancy(support string) *Tenancy {
	return &Tenancy{Support: support, accounts: map[string]*tenant{}, orgs: map[string]bool{}}
}

// Facts is the log in the order it was appended.
func (t *Tenancy) Facts() []Fact { return slices.Clone(t.facts) }

// ErrRefused wraps every operation this log declines; the message says why.
var ErrRefused = errors.New("tenancy: refused")

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// append writes the facts of one operation at time at. Time is the log's
// sequence: every operation comes strictly after the last, and the facts of one
// operation share its time.
func (t *Tenancy) append(at int64, fs ...Fact) error {
	if at <= t.now {
		return refused("time %d does not follow the log's last operation at %d", at, t.now)
	}
	t.now = at
	for _, f := range fs {
		f.T = at
		t.facts = append(t.facts, f)
	}
	return nil
}

func (t *Tenancy) person(a string) (*tenant, bool) {
	x, ok := t.accounts[a]
	return x, ok && !x.program && !x.gone
}

// Signup creates person a in the id directory and, in the same write, the
// personal org home it founds (§3 Signup). Nothing else is recorded (I19).
func (t *Tenancy) Signup(a, home string, at int64) error {
	switch {
	case t.accounts[a] != nil:
		return refused("account %s exists", a)
	case home == "" || Reserved(home):
		return refused("%q cannot be founded", home)
	case t.exists(home):
		return refused("org %s exists", home)
	}
	if err := t.append(at, Fact{Op: OpFounded, A: a, O: home, By: a}); err != nil {
		return err
	}
	t.accounts[a] = &tenant{owner: DirID, created: DirID}
	t.orgs[home] = true
	return nil
}

// Legacy records an account as it stands before §5 step 10: a person or program
// filed under an org, or a person filed under admin with no appointment behind it
// (§5 class A). It exists so the migration can be stated.
func (t *Tenancy) Legacy(a, owner string, program bool) error {
	if t.accounts[a] != nil {
		return refused("account %s exists", a)
	}
	if owner == DirID || owner == "" || (owner == DirAdmin && program) {
		return refused("a legacy account lives under an org, or is a person under admin, not %q", owner)
	}
	t.accounts[a] = &tenant{program: program, owner: owner, created: owner}
	return nil
}

// FoundHome records founded(a, home, by) with personal(home) for a person who
// has no org of one yet (§5 step 5).
func (t *Tenancy) FoundHome(a, home, by string, at int64) error {
	x, ok := t.person(a)
	switch {
	case !ok:
		return refused("%s is not a person", a)
	case x.owner == DirAdmin:
		return refused("a SuperAdmin holds no org (I2)")
	case t.Home(a) != "":
		return refused("%s already has an org of one", a)
	case home == "" || Reserved(home) || t.exists(home):
		return refused("%q cannot be founded", home)
	case by != a && !t.SuperAdmin(by):
		return refused("%s may not found for %s", by, a)
	}
	if err := t.append(at, Fact{Op: OpFounded, A: a, O: home, By: by}); err != nil {
		return err
	}
	t.orgs[home] = true
	return nil
}

// Found records founded(a, o, by) for a new, non-personal org (§3 Create an org):
// by is a itself, or a SuperAdmin provisioning it for a.
func (t *Tenancy) Found(a, o, by string, at int64) error {
	x, ok := t.person(a)
	switch {
	case !ok:
		return refused("%s is not a person", a)
	case x.owner == DirAdmin:
		return refused("a SuperAdmin never founds an org for themself (I2)")
	case o == "" || Reserved(o):
		return refused("%q is reserved", o)
	case t.exists(o):
		return refused("org %s exists", o)
	case by != a && !t.SuperAdmin(by):
		return refused("%s may not found for %s", by, a)
	}
	if err := t.append(at, Fact{Op: OpFounded, A: a, O: o, By: by}); err != nil {
		return err
	}
	t.orgs[o] = false
	return nil
}

// Enroll records assigned(p, o, r, by), the only way a program comes to act in an
// org: it creates program p in the id directory (§3 Create a program), or assigns
// a legacy program that acts in no org yet (§5 class E).
func (t *Tenancy) Enroll(p, o, r, by string, at int64) error {
	x, exists := t.accounts[p]
	if exists && !(x.program && !x.gone && x.owner != DirID && len(t.memberships(p)) == 0) {
		return refused("account %s exists", p)
	}
	if err := t.admits(by, o, r); err != nil {
		return err
	}
	if t.orgs[o] {
		return refused("a personal org has one member (I5)")
	}
	if err := t.append(at, Fact{Op: OpAssigned, A: p, O: o, R: r, By: by}); err != nil {
		return err
	}
	if !exists {
		t.accounts[p] = &tenant{program: true, owner: DirID, created: DirID}
	}
	return nil
}

// Invite records invited(n, o, m, r, by): one mailbox, one role, one use (§3).
func (t *Tenancy) Invite(n, o, m, r, by string, at int64) error {
	if n == "" || m == "" || t.invitation(n) != nil {
		return refused("invitation %q is unnamed, unaddressed or exists", n)
	}
	if err := t.admits(by, o, r); err != nil {
		return err
	}
	if t.orgs[o] {
		return refused("a personal org refuses invitations (I5)")
	}
	return t.append(at, Fact{Op: OpInvited, N: n, O: o, M: m, R: r, By: by})
}

// Accept records accepted(a, n). The caller has proven the invitation's mailbox;
// this log holds that the invitation stands, is unused, and admits a.
func (t *Tenancy) Accept(a, n string, at int64) error {
	x, ok := t.person(a)
	inv := t.invitation(n)
	switch {
	case !ok:
		return refused("%s is not a person", a)
	case x.owner == DirAdmin:
		return refused("a SuperAdmin holds no org role (I2)")
	case inv == nil:
		return refused("no invitation %s", n)
	case t.used(n):
		return refused("invitation %s is spent", n)
	case t.Member(a, inv.O):
		return refused("%s is already a member of %s", a, inv.O)
	}
	return t.append(at, Fact{Op: OpAccepted, A: a, N: n})
}

// Assign records assigned(a, o, r, by): a role change for an existing member,
// never a way in (§3 Role).
func (t *Tenancy) Assign(a, o, r, by string, at int64) error {
	cur := t.Role(a, o)
	if cur == "" {
		return refused("%s is not a member of %s", a, o)
	}
	if err := t.admits(by, o, r); err != nil {
		return err
	}
	if rank[cur] > rank[t.Role(by, o)] {
		return refused("%s outranks %s in %s", a, by, o)
	}
	if cur == RoleOwner && r != RoleOwner && t.owners(o) == 1 {
		return refused("the last owner of %s keeps the role (I7)", o)
	}
	return t.append(at, Fact{Op: OpAssigned, A: a, O: o, R: r, By: by})
}

// Revoke records revoked(a, o, by): by is a leaving, or an owner or admin of o
// who does not rank below a (§3 Revoke / leave).
func (t *Tenancy) Revoke(a, o, by string, at int64) error {
	cur := t.Role(a, o)
	switch {
	case cur == "":
		return refused("%s is not a member of %s", a, o)
	case t.orgs[o]:
		return refused("a personal org ends with its account")
	case cur == RoleOwner && t.owners(o) == 1:
		return refused("the last owner of %s cannot be revoked (I7)", o)
	case by != a && rank[t.Role(by, o)] < rank[RoleAdmin]:
		return refused("%s administers nothing in %s", by, o)
	case by != a && rank[cur] > rank[t.Role(by, o)]:
		return refused("%s outranks %s in %s", a, by, o)
	}
	return t.append(at, Fact{Op: OpRevoked, A: a, O: o, By: by})
}

// Assume records assumed(a, s, o): SuperAdmin a enters o for support, in token
// family s alone. It is not a role fact (§1).
func (t *Tenancy) Assume(a, s, o string, at int64) error {
	switch {
	case !t.SuperAdmin(a):
		return refused("only a SuperAdmin assumes")
	case s == "":
		return refused("an assume names its token family")
	case !t.exists(o) || Reserved(o):
		return refused("%q is not an org", o)
	}
	return t.append(at, Fact{Op: OpAssumed, A: a, S: s, O: o})
}

// Release records released(a, s) for the family a assumed in.
func (t *Tenancy) Release(a, s string, at int64) error {
	if t.assumed(s) == "" || t.assumer(s) != a {
		return refused("%s assumed nothing in family %s", a, s)
	}
	return t.append(at, Fact{Op: OpReleased, A: a, S: s})
}

// Switch records switched(a, o) when a is a member of o; "" returns to home.
func (t *Tenancy) Switch(a, o string, at int64) error {
	if o != "" && !t.Member(a, o) {
		return refused("%s is not a member of %s", a, o)
	}
	return t.append(at, Fact{Op: OpSwitched, A: a, O: o})
}

// Appoint creates SuperAdmin account a in the admin directory for person p
// (§3 Appoint a SuperAdmin): by is a SuperAdmin, or Genesis while the directory
// is empty (I18). It never moves or promotes an account.
func (t *Tenancy) Appoint(a, p, by string, at int64) error {
	x, ok := t.person(p)
	switch {
	case t.accounts[a] != nil:
		return refused("account %s exists", a)
	case !ok || x.owner == DirAdmin:
		return refused("%s is not a person outside the admin directory", p)
	case by == Genesis && t.superadmins() > 0:
		return refused("genesis appoints only while the admin directory is empty (I18)")
	case by != Genesis && !t.SuperAdmin(by):
		return refused("only a SuperAdmin appoints (I18)")
	}
	if err := t.append(at, Fact{Op: OpAppointed, A: a, P: p, By: by}); err != nil {
		return err
	}
	t.accounts[a] = &tenant{owner: DirAdmin, created: DirAdmin}
	return nil
}

// Dismiss records dismissed(a, by); the account leaves the admin directory. The
// last SuperAdmin is not dismissed.
func (t *Tenancy) Dismiss(a, by string, at int64) error {
	switch {
	case !t.SuperAdmin(a):
		return refused("%s is not a SuperAdmin", a)
	case !t.SuperAdmin(by):
		return refused("only a SuperAdmin dismisses")
	case t.superadmins() == 1:
		return refused("the last SuperAdmin is not dismissed")
	}
	if err := t.append(at, Fact{Op: OpDismissed, A: a, By: by}); err != nil {
		return err
	}
	t.accounts[a].gone = true
	return nil
}

// Move records moved(a, from, id), the one migration that sets owner(a) := id
// (§5 step 10). A person moves once it holds its org of one and a program once
// it acts in one org, so the move changes nothing the predicates read (L1). A
// person leaving admin (§5 class A) founds home, its org of one, in the same
// write; home is empty for every other move.
func (t *Tenancy) Move(a, home string, at int64) error {
	x, ok := t.accounts[a]
	switch {
	case !ok || x.gone:
		return refused("no account %s", a)
	case x.owner == DirID:
		return refused("%s already lives in id", a)
	case x.program && len(t.memberships(a)) != 1:
		return refused("program %s moves once it acts in one org", a)
	case !x.program && x.owner != DirAdmin && t.Home(a) == "":
		return refused("person %s moves once it holds its org of one", a)
	case x.owner == DirAdmin && (home == "" || Reserved(home) || t.exists(home)):
		return refused("%s leaves admin founding an org of one, not %q", a, home)
	case x.owner != DirAdmin && home != "":
		return refused("only an account leaving admin founds on the move")
	}
	fs := []Fact{{Op: OpMoved, A: a, From: x.owner}}
	if home != "" {
		fs = append(fs, Fact{Op: OpFounded, A: a, O: home, By: a})
	}
	if err := t.append(at, fs...); err != nil {
		return err
	}
	x.owner = DirID
	if home != "" {
		t.orgs[home] = true
	}
	return nil
}

// admits reports whether by may grant r in o: an owner or admin of o granting no
// more than its own role, in an org that is not reserved.
func (t *Tenancy) admits(by, o, r string) error {
	switch {
	case Reserved(o) || !t.exists(o):
		return refused("%q is not an org", o)
	case rank[r] == 0:
		return refused("%q is not a role", r)
	case rank[t.Role(by, o)] < rank[RoleAdmin]:
		return refused("%s administers nothing in %s", by, o)
	case rank[r] > rank[t.Role(by, o)]:
		return refused("%s grants no more than its own role", by)
	}
	return nil
}

func (t *Tenancy) exists(o string) bool {
	_, ok := t.orgs[o]
	return ok
}

// ---- the fold ----

// order is the canonical order of the log: time, then a fixed precedence so that
// facts sharing a time fold the same whichever was appended first. At one time a
// revocation outranks a grant.
func order(a, b Fact) int {
	if a.T != b.T {
		if a.T < b.T {
			return -1
		}
		return 1
	}
	if c := opRank[a.Op] - opRank[b.Op]; c != 0 {
		return c
	}
	return strings.Compare(a.key(), b.key())
}

var opRank = map[string]int{
	OpInvited: 0, OpFounded: 1, OpAccepted: 2, OpAssigned: 3, OpRevoked: 4,
	OpAppointed: 5, OpDismissed: 6, OpMoved: 7, OpSwitched: 8, OpAssumed: 9, OpReleased: 10,
}

func (f Fact) key() string {
	return strings.Join([]string{f.A, f.O, f.N, f.M, f.R, f.By, f.S, f.P, f.From}, "\x00")
}

func (t *Tenancy) sorted() []Fact {
	fs := slices.Clone(t.facts)
	slices.SortStableFunc(fs, order)
	return fs
}

func (t *Tenancy) invitation(n string) *Fact {
	for i := range t.facts {
		if t.facts[i].Op == OpInvited && t.facts[i].N == n {
			return &t.facts[i]
		}
	}
	return nil
}

func (t *Tenancy) used(n string) bool {
	for _, f := range t.facts {
		if f.Op == OpAccepted && f.N == n {
			return true
		}
	}
	return false
}

// SuperAdmin is superadmin(a) ⇔ owner(a) = admin ∧ kind(a) = person ∧
// ¬dismissed(a). It reads the account and nothing else (I16).
func (t *Tenancy) SuperAdmin(a string) bool {
	x, ok := t.accounts[a]
	return ok && x.owner == DirAdmin && !x.program && !x.gone
}

func (t *Tenancy) superadmins() int {
	n := 0
	for a := range t.accounts {
		if t.SuperAdmin(a) {
			n++
		}
	}
	return n
}

// Role is role(a, o): the last of founded, accepted, assigned and revoked about
// the pair, read as owner, the invitation's role, the assigned role, or none. It
// reads facts about (a, o) and nothing else (I15).
func (t *Tenancy) Role(a, o string) string {
	role := ""
	for _, f := range t.sorted() {
		switch f.Op {
		case OpFounded:
			if f.A == a && f.O == o {
				role = RoleOwner
			}
		case OpAccepted:
			if inv := t.invitation(f.N); f.A == a && inv != nil && inv.O == o {
				role = inv.R
			}
		case OpAssigned:
			if f.A == a && f.O == o {
				role = f.R
			}
		case OpRevoked:
			if f.A == a && f.O == o {
				role = ""
			}
		}
	}
	return role
}

// Member is member(a, o) ⇔ role(a, o) ≠ ⊥.
func (t *Tenancy) Member(a, o string) bool { return t.Role(a, o) != "" }

func (t *Tenancy) memberships(a string) []string {
	var out []string
	for o := range t.orgs {
		if t.Member(a, o) {
			out = append(out, o)
		}
	}
	slices.Sort(out)
	return out
}

func (t *Tenancy) owners(o string) int {
	n := 0
	for a := range t.accounts {
		if t.Role(a, o) == RoleOwner {
			n++
		}
	}
	return n
}

// Home is home(a): a person's org of one, the one org a program acts in, and ⊥
// for a SuperAdmin. It reads owner(a) only to tell admin and programs apart (L1).
func (t *Tenancy) Home(a string) string {
	x, ok := t.accounts[a]
	if !ok || x.gone || x.owner == DirAdmin {
		return ""
	}
	if x.program {
		if ms := t.memberships(a); len(ms) == 1 {
			return ms[0]
		}
		return ""
	}
	for _, f := range t.sorted() {
		if f.Op == OpFounded && f.A == a && t.orgs[f.O] {
			return f.O
		}
	}
	return ""
}

// Orgs is orgs(a) = [home(a)] ⧺ sort{o | member(a, o), o ≠ home(a)}, each with
// its role — the `orgs` claim.
func (t *Tenancy) Orgs(a string) []schema.OrgRef {
	home := t.Home(a)
	var out []schema.OrgRef
	if home != "" {
		out = append(out, schema.OrgRef{Org: home, Role: t.Role(a, home)})
	}
	for _, o := range t.memberships(a) {
		if o != home {
			out = append(out, schema.OrgRef{Org: o, Role: t.Role(a, o)})
		}
	}
	return out
}

func (t *Tenancy) assumed(s string) string {
	if s == "" {
		return ""
	}
	org := ""
	for _, f := range t.sorted() {
		if f.S != s {
			continue
		}
		switch f.Op {
		case OpAssumed:
			org = f.O
		case OpReleased:
			org = ""
		}
	}
	return org
}

func (t *Tenancy) assumer(s string) string {
	a := ""
	for _, f := range t.sorted() {
		if f.Op == OpAssumed && f.S == s {
			a = f.A
		}
	}
	return a
}

func (t *Tenancy) switched(a string) string {
	org := ""
	for _, f := range t.sorted() {
		if f.Op == OpSwitched && f.A == a {
			org = f.O
		}
	}
	return org
}

// Acting is acting(s) for account a in token family s: the assumed org, else the
// org a switched to while a is its member, else home(a).
func (t *Tenancy) Acting(a, s string) string {
	if o := t.assumed(s); o != "" {
		return o
	}
	if o := t.switched(a); o != "" && t.Member(a, o) {
		return o
	}
	return t.Home(a)
}

// Payer is payer(s): Support under an assume, else the acting org. ⊥ — a
// SuperAdmin outside an assume — refuses every metered call.
func (t *Tenancy) Payer(a, s string) string {
	if t.assumed(s) != "" {
		return t.Support
	}
	return t.Acting(a, s)
}

// Violations evaluates I1–I9, I12, I14 and I18 on the fold and names every
// breach. An account still filed under a legacy org is a breach of I4 and I8, and
// a person under admin with no appointment a breach of I18, until §5 step 10
// moves it.
func (t *Tenancy) Violations() []string {
	var out []string
	bad := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	subs := make([]string, 0, len(t.accounts))
	for a := range t.accounts {
		subs = append(subs, a)
	}
	slices.Sort(subs)
	orgs := make([]string, 0, len(t.orgs))
	for o := range t.orgs {
		orgs = append(orgs, o)
	}
	slices.Sort(orgs)
	for _, a := range subs {
		x := t.accounts[a]
		if x.gone {
			continue
		}
		super := t.SuperAdmin(a)
		if super != (x.owner == DirAdmin && !x.program) {
			bad("I1 %s", a)
		}
		if super && len(t.memberships(a)) > 0 {
			bad("I2 %s holds a role", a)
		}
		for _, o := range t.memberships(a) {
			if Reserved(o) {
				bad("I3 %s is a member of %s", a, o)
			}
		}
		if !x.program && x.owner != DirAdmin {
			n := 0
			for _, f := range t.facts {
				if f.Op == OpFounded && f.A == a && t.orgs[f.O] {
					n++
				}
			}
			if n != 1 {
				bad("I4 %s holds %d orgs of one", a, n)
			}
		}
		if x.owner != DirID && x.owner != DirAdmin {
			bad("I8 %s lives under %s", a, x.owner)
		}
		if x.owner == DirAdmin && x.program {
			bad("I8 program %s lives under admin", a)
		}
		if x.owner != x.created && !(x.owner == DirID && t.moved(a)) {
			bad("I12 %s was rewritten from %s to %s", a, x.created, x.owner)
		}
		if x.owner == DirAdmin && !super {
			bad("I14 %s lives under admin", a)
		}
		if x.owner == DirAdmin && !t.appointed(a) {
			bad("I18 %s lives under admin with no appointment", a)
		}
		for _, s := range t.families(a) {
			p := t.Payer(a, s)
			if p != "" && !t.Member(a, p) && !(p == t.Support && t.assumed(s) != "") {
				bad("I9 %s/%s pays from %s", a, s, p)
			}
		}
	}
	for _, o := range orgs {
		members, founders := 0, 0
		for _, a := range subs {
			if t.Member(a, o) {
				members++
			}
		}
		for _, f := range t.facts {
			if f.Op == OpFounded && f.O == o {
				founders++
			}
		}
		if t.orgs[o] && members != 1 {
			bad("I5 personal org %s has %d members", o, members)
		}
		if founders != 1 {
			bad("I6 org %s has %d founders", o, founders)
		}
		if t.owners(o) == 0 {
			bad("I7 org %s has no owner", o)
		}
	}
	return out
}

func (t *Tenancy) appointed(a string) bool {
	for _, f := range t.facts {
		if f.Op == OpAppointed && f.A == a {
			return true
		}
	}
	return false
}

func (t *Tenancy) moved(a string) bool {
	for _, f := range t.facts {
		if f.Op == OpMoved && f.A == a {
			return true
		}
	}
	return false
}

// families is every token family the log names for a, and the unnamed one.
func (t *Tenancy) families(a string) []string {
	out := []string{""}
	for _, f := range t.facts {
		if f.S != "" && f.A == a && !slices.Contains(out, f.S) {
			out = append(out, f.S)
		}
	}
	return out
}

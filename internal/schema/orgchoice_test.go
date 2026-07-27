// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package schema

import "testing"

// THE ALLOWLIST, PINNED TO THE MODES IAM ITSELF WRITES.
//
// AllowsOrgChoice is an allowlist so an unanticipated value gates rather than
// waves through. That is the right shape, but the first spelling of the list —
// {"select","input"} — was drawn from Casdoor's chooser widgets alone and left out
// the one mode IAM defines in its OWN code: "create", the per-application opt-in to
// self-serve organization creation (oidc.orgChoiceCreate, read in signupHandler).
//
// Measured on live IAM (281 registered applications, read from the running pod's
// store, not inferred): hanzo-console and hanzo-cloud both carry
// orgChoiceMode="create". They are the two surfaces that mint a founder's own org
// at signup and then let that founder sign back in. Omitting "create" from the
// allowlist gates exactly them — signup could no longer create the org (the tenant
// check refuses the foreign org before the create branch is ever reached) and every
// existing founder would be refused at login. The gate would have been strictly
// self-defeating: it locks out the users it exists to keep separated, while the
// apps it was written for are unaffected.
//
// So the allowlist is the modes that actually let a human land in an org other than
// the app's own, by any mechanism: pick one (select), type one (input), or make one
// (create).
func TestAllowsOrgChoice(t *testing.T) {
	for _, c := range []struct {
		mode string
		want bool
	}{
		// The three real chooser modes, including the casing/padding drift the
		// trim+lowercase comparison exists to absorb.
		{"select", true}, {"input", true}, {"create", true},
		{"Select", true}, {"Input", true}, {"Create", true},
		{" CREATE ", true},

		// No chooser. "None" is Casdoor's default and what most live rows hold; ""
		// is the other spelling of the same state. Both must gate, or one value
		// silently disables the control.
		{"None", false}, {"none", false}, {"", false}, {"   ", false},

		// Fail closed: a value nobody anticipated is not a chooser.
		{"any", false}, {"true", false}, {"maybe-later", false},
	} {
		a := &Application{OrgChoiceMode: c.mode}
		if got := a.AllowsOrgChoice(); got != c.want {
			t.Errorf("AllowsOrgChoice(%q) = %v, want %v", c.mode, got, c.want)
		}
	}
}

// ServesOrg is the whole tenant gate, so pin its three ways to say yes and the one
// way to say no — against the shapes live IAM actually carries.
func TestServesOrg(t *testing.T) {
	for _, c := range []struct {
		name string
		app  *Application
		org  string
		want bool
	}{
		// An app serves its own org whatever the mode.
		{"own org, no chooser", &Application{Organization: "hanzo", OrgChoiceMode: "None"}, "hanzo", true},

		// The steady state of a brand app after self-service onboarding: the founder
		// has been moved into their OWN org, so owner != app.Organization. Only an
		// honest IsShared, or a chooser, may let them back in.
		{"foreign org, None, not shared", &Application{Organization: "hanzo", OrgChoiceMode: "None"}, "acme", false},
		{"foreign org, None, shared", &Application{Organization: "hanzo", OrgChoiceMode: "None", IsShared: true}, "acme", true},

		// hanzo-console / hanzo-cloud as they exist in production today.
		{"foreign org, create", &Application{Organization: "hanzo", OrgChoiceMode: "create"}, "acme", true},

		// hanzo-cli / hanzo-mcp: no mode at all, single-tenant, must stay closed.
		{"foreign org, empty mode", &Application{Organization: "hanzo"}, "acme", false},

		// Fail closed on the degenerate inputs. An empty org is never served: it is
		// what a caller that failed to resolve a tenant passes, and treating it as a
		// match against an app with an empty Organization would open everything.
		{"empty org", &Application{Organization: "hanzo", IsShared: true}, "", false},
		{"nil app", nil, "hanzo", false},
	} {
		if got := c.app.ServesOrg(c.org); got != c.want {
			t.Errorf("%s: ServesOrg(%q) = %v, want %v", c.name, c.org, got, c.want)
		}
	}
}

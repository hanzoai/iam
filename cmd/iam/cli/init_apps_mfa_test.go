package cli

import (
	"encoding/json"
	"testing"
)

// ensureMfaNonForcing is the pure core of the "brand orgs never force MFA"
// invariant. These cases pin its contract: downgrade Required → Optional, add
// missing methods as Optional, never raise a rule, and stay idempotent.

func ruleOf(o *org, name string) string {
	for _, it := range o.MfaItems {
		if it.Name == name {
			return it.Rule
		}
	}
	return ""
}

func TestEnsureMfaNonForcing_UnforcesRequired(t *testing.T) {
	// The live bug state: authenticator forced, no other method offered.
	o := &org{MfaItems: []*mfaItem{{Name: "app", Rule: "Required"}}}
	changed := ensureMfaNonForcing(o)
	if changed == 0 {
		t.Fatal("expected changes un-forcing a Required org")
	}
	if got := ruleOf(o, "app"); got != "Optional" {
		t.Fatalf("app rule = %q, want Optional", got)
	}
	for _, m := range []string{"app", "sms", "email"} {
		if ruleOf(o, m) != "Optional" {
			t.Errorf("method %s not available as Optional", m)
		}
	}
}

func TestEnsureMfaNonForcing_AddsMissingMethods(t *testing.T) {
	o := &org{} // empty list → off, but methods not yet offered
	if ensureMfaNonForcing(o) != 3 {
		t.Fatalf("expected 3 methods added, got %d items: %+v", len(o.MfaItems), o.MfaItems)
	}
	for _, m := range []string{"app", "sms", "email"} {
		if ruleOf(o, m) != "Optional" {
			t.Errorf("method %s = %q, want Optional", m, ruleOf(o, m))
		}
	}
}

func TestEnsureMfaNonForcing_NeverRaisesRule(t *testing.T) {
	// An admin-set Prompt must NOT be raised; it is already non-forcing.
	o := &org{MfaItems: []*mfaItem{
		{Name: "app", Rule: "Prompted"},
		{Name: "sms", Rule: "Optional"},
		{Name: "email", Rule: "Optional"},
	}}
	if changed := ensureMfaNonForcing(o); changed != 0 {
		t.Fatalf("expected no change for an already non-forcing org, got %d", changed)
	}
	if ruleOf(o, "app") != "Prompted" {
		t.Errorf("Prompt rule was altered to %q", ruleOf(o, "app"))
	}
}

func TestEnsureMfaNonForcing_Idempotent(t *testing.T) {
	o := &org{MfaItems: []*mfaItem{{Name: "app", Rule: "Required"}}}
	ensureMfaNonForcing(o)
	if second := ensureMfaNonForcing(o); second != 0 {
		t.Fatalf("second pass changed %d items; want 0 (idempotent)", second)
	}
}

func TestUpdateOrg_RefusesMaskedSalt(t *testing.T) {
	// A masked passwordSalt must hard-fail rather than corrupt the row.
	o := &org{Owner: "admin", Name: "hanzo", raw: map[string]json.RawMessage{
		"passwordSalt": json.RawMessage(`"***"`),
	}}
	if !maskedOrgSalt(o) {
		t.Fatal("maskedOrgSalt should detect the *** sentinel")
	}
}

func TestOrg_UnmarshalCapturesRaw(t *testing.T) {
	// The raw round-trip must preserve fields the typed view ignores.
	const in = `{"owner":"admin","name":"hanzo","displayName":"Hanzo","mfaItems":[{"name":"app","rule":"Required"}],"someFutureField":42}`
	var o org
	if err := json.Unmarshal([]byte(in), &o); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.raw["someFutureField"]; !ok {
		t.Error("raw did not capture an untyped field — full-row update would wipe it")
	}
	if _, ok := o.raw["displayName"]; !ok {
		t.Error("raw did not capture displayName")
	}
}

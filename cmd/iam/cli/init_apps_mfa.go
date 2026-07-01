package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// MFA convergence for brand orgs — the remediation half of the "don't force
// 2FA" policy. buildOrg ships NEW brand orgs with non-forcing MFA; this
// un-forces EXISTING ones whose live row still carries a Required rule (the
// forced-authenticator state users hit on hanzo.id). It is a one-way, idempotent
// invariant: *brand orgs never force MFA*. It only ever DOWNGRADES Required →
// Optional and ADDS missing methods as Optional — it never raises a rule, so it
// can't override an admin who has, say, set a method to Prompt; and it touches
// only the orgs in brandSpecs, so a tenant's own org + its deliberate Required
// is untouched. Per-org enforcement remains a live Settings → MFA items choice;
// this just guarantees the shipped brand default is "available, not forced".

// org is the typed+raw view of an organization, mirroring `app`: the typed
// fields are what we converge; `raw` is the complete row, written back
// byte-for-byte so a full-row update wipes nothing.
type org struct {
	Owner    string     `json:"owner"`
	Name     string     `json:"name"`
	MfaItems []*mfaItem `json:"mfaItems"`

	raw map[string]json.RawMessage
}

// UnmarshalJSON decodes the typed view AND captures the full row into raw (the
// `alias` indirection breaks org's method set so the inner decode can't recurse).
func (o *org) UnmarshalJSON(b []byte) error {
	type alias org
	if err := json.Unmarshal(b, (*alias)(o)); err != nil {
		return err
	}
	return json.Unmarshal(b, &o.raw)
}

// getOrg fetches one organization (full row) from /v1/iam/get-organization.
func getOrg(c *provClient, adminOrg, name string) (*org, error) {
	q := url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", adminOrg, name))
	var o org
	if err := c.get("/v1/iam/get-organization", q, &o); err != nil {
		return nil, err
	}
	if o.Name == "" {
		return nil, nil
	}
	return &o, nil
}

// ensureMfaNonForcing converges o.MfaItems to the brand policy in place and
// reports how many items changed (0 = already non-forcing). It DOWNGRADES any
// Required rule to Optional and ADDS any missing canonical method as Optional;
// it never raises a rule. Pure — no I/O — so it is unit-testable.
func ensureMfaNonForcing(o *org) int {
	changed := 0
	have := map[string]*mfaItem{}
	for _, it := range o.MfaItems {
		have[it.Name] = it
	}
	// Un-force: a Required rule is the bug state → Optional.
	for _, it := range o.MfaItems {
		if it.Rule == "Required" {
			it.Rule = "Optional"
			changed++
		}
	}
	// Ensure every canonical method is at least available (Optional).
	for _, want := range nonForcingMfaItems {
		if have[want.Name] == nil {
			o.MfaItems = append(o.MfaItems, &mfaItem{Name: want.Name, Rule: "Optional"})
			changed++
		}
	}
	return changed
}

// maskedOrgSalt reports whether the org's password_salt came back masked. A
// salted org (e.g. legacy non-argon2id) returns PasswordSalt="***"; writing
// that back on a full-row replace would corrupt logins — so we refuse, exactly
// like updateApp's masked-secret guard. Brand orgs use argon2id (salt embedded
// in the hash, column empty → never masked), so this never trips for them.
func maskedOrgSalt(o *org) bool {
	return maskedSecret(o.raw["passwordSalt"])
}

// updateOrg writes the org back via /v1/iam/update-organization (a full-row
// replace), starting from raw so every untouched field round-trips verbatim and
// overwriting ONLY mfaItems from the converged typed value.
func updateOrg(c *provClient, o *org) error {
	if maskedOrgSalt(o) {
		return fmt.Errorf("refusing to update org %s/%s: passwordSalt is masked (%q); the provisioning client must read it unmasked", o.Owner, o.Name, "***")
	}
	body := map[string]json.RawMessage{}
	for k, v := range o.raw {
		body[k] = v
	}
	if b, err := json.Marshal(o.MfaItems); err == nil {
		body["mfaItems"] = b
	}
	q := url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", o.Owner, o.Name))
	var ok string
	return c.postJSON("/v1/iam/update-organization", q, body, &ok)
}

// ensureOrgMfaNonForcing fetches a brand org, converges its MFA to the
// non-forcing brand policy, and writes it back only if something changed.
// Returns true when it un-forced/extended the org (for the reconcile summary).
func ensureOrgMfaNonForcing(c *provClient, adminOrg, name string, verbose bool) (bool, error) {
	o, err := getOrg(c, adminOrg, name)
	if err != nil {
		return false, fmt.Errorf("get org %s: %w", name, err)
	}
	if o == nil {
		return false, nil // org not present yet (caller creates it non-forcing)
	}
	o.Owner = adminOrg
	if changed := ensureMfaNonForcing(o); changed == 0 {
		if verbose {
			fmt.Printf("[skip] %s — MFA already non-forcing\n", name)
		}
		return false, nil
	}
	if err := updateOrg(c, o); err != nil {
		return false, fmt.Errorf("un-force MFA %s: %w", name, err)
	}
	if verbose {
		fmt.Printf("[mfa]  %s — converged MFA to non-forcing (Optional)\n", name)
	}
	return true, nil
}

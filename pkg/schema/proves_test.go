package schema

import "testing"

// Proves is the one rule every client-authenticating endpoint applies: a
// registration with no secret has nothing to prove, and one with a secret is
// proved by that secret alone.
func TestApplicationProves(t *testing.T) {
	public := &Application{}
	confidential := &Application{ClientSecret: "s3cr3t"}
	for _, c := range []struct {
		app    *Application
		secret string
		want   bool
	}{
		{public, "", true},
		{public, "anything", true},
		{confidential, "s3cr3t", true},
		{confidential, "", false},
		{confidential, "s3cr3", false},
		{confidential, "s3cr3t ", false},
	} {
		if got := c.app.Proves(c.secret); got != c.want {
			t.Errorf("secret %q against %q: Proves = %v, want %v", c.secret, c.app.ClientSecret, got, c.want)
		}
	}
}

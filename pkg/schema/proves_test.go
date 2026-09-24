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

// A person with no image is drawn from Gravatar, keyed by the normalized
// address; one with an image keeps it.
func TestUserPicture(t *testing.T) {
	a := (&User{Email: "  Z@Hanzo.AI "}).Picture()
	b := (&User{Email: "z@hanzo.ai"}).Picture()
	if a != b || len(a) != len("https://gravatar.com/avatar/")+64+len("?d=identicon&s=256") {
		t.Fatalf("gravatar not normalized or malformed: %q vs %q", a, b)
	}
	if got := (&User{Email: "z@hanzo.ai", Avatar: "https://x/y.png"}).Picture(); got != "https://x/y.png" {
		t.Fatalf("an image set by the person must win, got %q", got)
	}
	if got := (&User{}).Picture(); got != "" {
		t.Fatalf("no image and no address draws nothing, got %q", got)
	}
}

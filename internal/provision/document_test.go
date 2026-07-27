package provision

import (
	"os"
	"strings"
	"testing"
)

// TestShippedDocument derives a real org document from disk, so a change to a
// shipped provision.yaml is caught here instead of in production. Each org
// repo points this at its own file in CI:
//
//	IAM_PROVISION_DOC=infra/k8s/iam/provision.yaml go test ./internal/provision/
func TestShippedDocument(t *testing.T) {
	path := os.Getenv("IAM_PROVISION_DOC")
	if path == "" {
		t.Skip("set IAM_PROVISION_DOC to check a shipped document")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(raw)
	if err != nil {
		t.Fatalf("shipped document does not parse: %v", err)
	}
	cs, err := Derive(d)
	if err != nil {
		t.Fatalf("shipped document does not derive: %v", err)
	}
	for _, c := range cs {
		t.Logf("%-16s %s", c.Name, strings.Join(c.RedirectUris, " "))
	}
	if len(cs) == 0 {
		t.Fatal("shipped document derived no clients")
	}
}

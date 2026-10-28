package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialFileRequiresNativeReaderAndKeepsAssertionPrivate(t *testing.T) {
	for _, role := range []string{"reader", "machine"} {
		t.Run(role, func(t *testing.T) {
			iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.ParseForm()
				if r.Form.Get("assertion") != "projected.assertion" {
					t.Error("wrong assertion")
				}
				json.NewEncoder(w).Encode(map[string]any{"access_token": "eyNative.e30.signature", "expires_in": 3600})
			}))
			defer iam.Close()
			forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer eyNative.e30.signature" {
					t.Error("wrong bearer")
				}
				json.NewEncoder(w).Encode(map[string]any{"authority": "hanzo-iam", "issuer": "https://hanzo.id", "credentialRole": role})
			}))
			defer forge.Close()
			dir := t.TempDir()
			assertion := filepath.Join(dir, "assertion")
			os.WriteFile(assertion, []byte("projected.assertion"), 0600)
			t.Setenv("HANZO_SA_TOKEN", assertion)
			t.Setenv("HANZO_IAM_URL", iam.URL)
			out := filepath.Join(dir, "file", "token")
			cmd := workloadCredentialCmd()
			cmd.SetArgs([]string{"token", "--out", out, "--forge-reader", forge.URL})
			e := cmd.Execute()
			if role != "reader" {
				if e == nil {
					t.Fatal("machine admitted as reader")
				}
				if _, e = os.Stat(out); !os.IsNotExist(e) {
					t.Fatal("refused bearer reached file")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			b, e := os.ReadFile(out)
			if e != nil || string(b) != "eyNative.e30.signature" {
				t.Fatal("wrong credential file")
			}
			st, _ := os.Stat(out)
			if st.Mode().Perm() != 0400 {
				t.Fatal("credential file is not owner read-only")
			}
		})
	}
}

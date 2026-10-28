package workload

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExchangeUsesNativeAssertionGrantAndExpiry(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.Form.Get("assertion") != "projected.assertion" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("wrong native grant")
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "eyNative.e30.signature", "expires_in": 3600})
	}))
	defer s.Close()
	tok, e := Exchange(context.Background(), s.URL, "projected.assertion\n", nil)
	if e != nil || tok == nil || time.Until(tok.Expiry) < 59*time.Minute {
		t.Fatalf("token exchange: %v", e)
	}
}
func TestExchangeRefusesAndDoesNotExposeResponseCredentials(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("private-response-credential"))
	}))
	defer s.Close()
	_, e := Exchange(context.Background(), s.URL, "projected.assertion", nil)
	if e == nil || strings.Contains(e.Error(), "private-response-credential") {
		t.Fatal("unsafe refusal")
	}
}

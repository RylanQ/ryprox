// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardChallenges(t *testing.T) {
	// Stands in for the primary's port 80.
	ln, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Skip("can't listen on port 80 here:", err)
	}
	primary := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("token-for " + r.Host + r.URL.Path))
	})}
	go func() { _ = primary.Serve(ln) }()
	defer func() { _ = primary.Close() }()

	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("local")) })
	h := forwardChallenges(local, "https://login.example.com", "127.0.0.1:443")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://app.example.com/.well-known/acme-challenge/abc", nil))
	if rec.Body.String() != "token-for app.example.com/.well-known/acme-challenge/abc" {
		t.Fatalf("challenge: %q", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://app.example.com/other", nil))
	if rec.Body.String() != "local" {
		t.Fatalf("other path: %q", rec.Body.String())
	}
}

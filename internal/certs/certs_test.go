// SPDX-License-Identifier: AGPL-3.0-only

package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rylanq/ryprox/internal/store"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestOffByDefault(t *testing.T) {
	m := New(t.TempDir(), func(string) bool { return true }, quiet())
	m.Configure(store.Settings{TLSMode: store.TLSModeOff})
	if m.Enabled() {
		t.Fatal("enabled in off mode")
	}
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err == nil {
		t.Fatal("served a certificate with HTTPS off")
	}
	if st := m.Status("a.example.com"); st.State != "off" {
		t.Fatalf("state = %s", st.State)
	}
	// HTTP handler passes straight through.
	rec := httptest.NewRecorder()
	m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })).
		ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), "GET", "http://a.example.com/", nil))
	if rec.Code != 299 {
		t.Fatalf("fallback not used: %d", rec.Code)
	}
}

func TestUnknownHostsRefused(t *testing.T) {
	m := New(t.TempDir(), func(h string) bool { return h == "ok.example.com" }, quiet())
	m.Configure(store.Settings{TLSMode: store.TLSModeACME, ACMEEmail: "a@example.com", ACMEStaging: true})
	// A stranger pointing a random name at us must not trigger a certificate request.
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "random.example.org"}); err == nil {
		t.Fatal("certificate requested for an unconfigured host")
	}
	if st := m.Status("random.example.org"); st.Error != "" {
		t.Fatal("errors for unknown hosts should not be recorded")
	}
}

func TestStatusReadsCachedCertificate(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, func(string) bool { return true }, quiet())
	m.Configure(store.Settings{TLSMode: store.TLSModeACME, ACMEEmail: "a@example.com", ACMEStaging: true})

	if st := m.Status("app.example.com"); st.State != "pending" || !st.Staging {
		t.Fatalf("before: %+v", st)
	}

	// Write a certificate in autocert's cache format: key, then chain.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
		DNSNames:     []string{"app.example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	cache := filepath.Join(dir, "letsencrypt-staging")
	_ = os.MkdirAll(cache, 0o700)
	if err := os.WriteFile(filepath.Join(cache, "app.example.com"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	st := m.Status("app.example.com")
	if st.State != "valid" || st.NotAfter.Before(time.Now().Add(59*24*time.Hour)) {
		t.Fatalf("after: %+v", st)
	}
}

func TestStagingAndProductionUseSeparateCaches(t *testing.T) {
	m := New(t.TempDir(), func(string) bool { return true }, quiet())
	m.Configure(store.Settings{TLSMode: store.TLSModeACME, ACMEEmail: "a@example.com", ACMEStaging: true})
	staging := m.cacheDir
	m.Configure(store.Settings{TLSMode: store.TLSModeACME, ACMEEmail: "a@example.com"})
	if m.cacheDir == staging {
		t.Fatal("staging and production share a certificate cache")
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

// Package certs gets and renews HTTPS certificates from Let's Encrypt
// automatically, for exactly the hostnames RyProx is configured to serve.
package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/rylanq/ryprox/internal/store"
)

// Let's Encrypt's test ("staging") directory. Certificates from it are not
// trusted by browsers, but it has much higher rate limits, so it's ideal
// for trying RyProx out.
const stagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// Manager wraps autocert so its settings can change while running.
type Manager struct {
	dir     string
	allowed func(host string) bool
	log     *slog.Logger

	// Optional custom ACME server (e.g. a private step-ca), set at startup.
	customURL    string
	customClient *http.Client

	mu       sync.RWMutex
	m        *autocert.Manager
	settings store.Settings
	cacheDir string
	errs     map[string]hostError
	pending  map[string]bool
}

type hostError struct {
	msg string
	at  time.Time
}

// New returns a manager storing certificates under dir. allowed decides
// which hostnames may get certificates; anything else is refused, so
// strangers can't make RyProx request certificates for random names.
func New(dir string, allowed func(host string) bool, log *slog.Logger) *Manager {
	return &Manager{dir: dir, allowed: allowed, log: log, errs: map[string]hostError{}, pending: map[string]bool{}}
}

// UseCustomServer makes RyProx get certificates from a different ACME
// server instead of Let's Encrypt. caFile, if set, is a PEM file of extra
// root certificates to trust when talking to that server.
func (c *Manager) UseCustomServer(directoryURL, caFile string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	if caFile != "" {
		pemData, err := os.ReadFile(caFile) //nolint:gosec // path comes from the operator's own flag
		if err != nil {
			return fmt.Errorf("read ACME CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return errors.New("ACME CA file contains no certificates")
		}
		client.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.customURL, c.customClient = directoryURL, client
	c.m = nil // rebuilt on next Configure
	return nil
}

// Configure applies new settings. It is cheap to call when nothing changed.
func (c *Manager) Configure(s store.Settings) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m != nil && c.settings.TLSMode == s.TLSMode && c.settings.ACMEEmail == s.ACMEEmail && c.settings.ACMEStaging == s.ACMEStaging {
		c.settings = s
		return
	}
	c.settings = s
	c.errs = map[string]hostError{}
	if s.TLSMode != store.TLSModeACME {
		c.m = nil
		return
	}
	sub, dirURL := "letsencrypt", acme.LetsEncryptURL
	var httpClient *http.Client
	switch {
	case c.customURL != "":
		sub, dirURL, httpClient = "custom", c.customURL, c.customClient
	case s.ACMEStaging:
		// Keep test certificates apart so they're never served in production.
		sub, dirURL = "letsencrypt-staging", stagingURL
	}
	c.cacheDir = filepath.Join(c.dir, sub)
	c.m = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  s.ACMEEmail,
		Cache:  autocert.DirCache(c.cacheDir),
		HostPolicy: func(_ context.Context, host string) error {
			if c.allowed(host) {
				return nil
			}
			return fmt.Errorf("RyProx is not configured to serve %q", host)
		},
		Client: &acme.Client{DirectoryURL: dirURL, UserAgent: "RyProx", HTTPClient: httpClient},
	}
	// autocert only offers the port-80 (HTTP-01) challenge once its HTTP
	// handler exists. Create it now so both port 80 and port 443 challenges
	// work from the very first certificate.
	_ = c.m.HTTPHandler(nil)
}

func (c *Manager) current() *autocert.Manager {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.m
}

// Enabled reports whether automatic HTTPS is on.
func (c *Manager) Enabled() bool { return c.current() != nil }

// GetCertificate is used by the HTTPS listener.
func (c *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m := c.current()
	if m == nil {
		return nil, errors.New("HTTPS is turned off")
	}
	cert, err := m.GetCertificate(hello)
	if err != nil && hello.ServerName != "" && c.allowed(hello.ServerName) {
		c.recordError(hello.ServerName, err)
	} else if err == nil {
		c.clearError(hello.ServerName)
	}
	return cert, err
}

// TLSConfig returns the configuration for the HTTPS listener.
func (c *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: c.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}
}

// HTTPHandler answers Let's Encrypt's HTTP challenges and passes
// everything else to fallback.
func (c *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := c.current(); m != nil {
			m.HTTPHandler(fallback).ServeHTTP(w, r)
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

func (c *Manager) recordError(host string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs[host] = hostError{msg: err.Error(), at: time.Now()}
}

func (c *Manager) clearError(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.errs, host)
}

// Obtain requests a certificate for host in the background, so it's ready
// before the first visitor arrives.
func (c *Manager) Obtain(host string) {
	if !c.Enabled() || !c.allowed(host) {
		return
	}
	c.mu.Lock()
	if c.pending[host] {
		c.mu.Unlock()
		return
	}
	c.pending[host] = true
	c.mu.Unlock()
	go func() {
		defer func() {
			c.mu.Lock()
			delete(c.pending, host)
			c.mu.Unlock()
		}()
		hello := &tls.ClientHelloInfo{
			ServerName:        host,
			SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
			SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves:   []tls.CurveID{tls.CurveP256},
			CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		}
		if _, err := c.GetCertificate(hello); err != nil {
			c.log.Warn("could not get certificate", "host", host, "err", err)
		} else {
			c.log.Info("certificate ready", "host", host)
		}
	}()
}

// Status describes a hostname's certificate for the UI.
type Status struct {
	Host      string    `json:"host"`
	State     string    `json:"state"` // "valid", "pending", "error", "off"
	Issuer    string    `json:"issuer,omitempty"`
	NotAfter  time.Time `json:"notAfter,omitzero"`
	Staging   bool      `json:"staging"`
	Error     string    `json:"error,omitempty"`
	ErrorTime time.Time `json:"errorTime,omitzero"`
}

// Status reports the certificate state for host.
func (c *Manager) Status(host string) Status {
	c.mu.RLock()
	m, dir, staging := c.m, c.cacheDir, c.settings.ACMEStaging
	he, hasErr := c.errs[host]
	pending := c.pending[host]
	c.mu.RUnlock()

	st := Status{Host: host, Staging: staging}
	if m == nil {
		st.State = "off"
		return st
	}
	if leaf := readLeaf(filepath.Join(dir, host)); leaf != nil {
		st.State = "valid"
		st.Issuer = leaf.Issuer.CommonName
		st.NotAfter = leaf.NotAfter
		if time.Now().After(leaf.NotAfter) {
			st.State = "expired"
		}
	} else {
		st.State = "pending"
	}
	if hasErr && !pending {
		st.Error, st.ErrorTime = he.msg, he.at
		if st.State != "valid" {
			st.State = "error"
		}
	}
	return st
}

// readLeaf reads autocert's cache file (private key followed by the
// certificate chain) and returns the first certificate.
func readLeaf(path string) *x509.Certificate {
	data, err := os.ReadFile(path) //nolint:gosec // path is built from a validated hostname
	if err != nil {
		return nil
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil
		}
		if b.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil
			}
			return cert
		}
	}
}

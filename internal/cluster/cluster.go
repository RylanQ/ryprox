// SPDX-License-Identifier: AGPL-3.0-only

// Package cluster runs RyProx on several servers. One primary holds the
// configuration and gets certificates; followers mirror its configuration,
// secret key and certificates every few seconds and serve traffic too.
//
// Put the servers behind DNS with health checks (or a floating IP). If the
// primary goes down, followers keep serving with the last configuration.
// To make a follower the new primary, restart it without --follow.
//
// Changes can only be made on the primary; a follower's dashboard is
// read-only. Each server keeps its own sign-in sessions and activity log.
package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rylanq/ryprox/internal/store"
)

// TokenPrefix starts every follower token.
const TokenPrefix = "ryn_"

// Path is where followers sync from, on the primary's sign-in domain.
const Path = "/.ryprox/node/sync"

// Interval between syncs.
var Interval = 15 * time.Second

// maxPayload bounds a snapshot.
const maxPayload = 64 << 20

// Payload is what the primary sends.
type Payload struct {
	Version   int               `json:"version"`
	SecretKey string            `json:"secretKey"` // base64 of secret.key
	Config    store.Snapshot    `json:"config"`
	Certs     map[string]string `json:"certs"`   // path under certs/ → base64 contents
	CertDir   string            `json:"certDir"` // the primary's certificate folder, e.g. "letsencrypt"
	Hash      string            `json:"hash"`    // changes when anything above changes
}

// BuildPayload collects the primary's state.
func BuildPayload(ctx context.Context, st *store.Store, dataDir, certDir string) (*Payload, error) {
	key, err := os.ReadFile(filepath.Join(dataDir, "secret.key"))
	if err != nil {
		return nil, err
	}
	snap, err := st.ExportConfig(ctx)
	if err != nil {
		return nil, err
	}
	p := &Payload{Version: 1, SecretKey: base64.StdEncoding.EncodeToString(key), Config: snap, Certs: map[string]string{}, CertDir: certDir}
	certRoot := filepath.Join(dataDir, "certs")
	_ = filepath.WalkDir(certRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(certRoot, path)
		if err != nil {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // inside our own data directory
		if err == nil {
			p.Certs[filepath.ToSlash(rel)] = base64.StdEncoding.EncodeToString(b)
		}
		return nil
	})
	b, _ := json.Marshal([]any{p.SecretKey, p.Config, p.Certs, p.CertDir})
	p.Hash = fmt.Sprintf("%x", sha(b))
	return p, nil
}

// Status is the follower's view, shown in its dashboard.
type Status struct {
	Primary  string    `json:"primary"`
	LastSync time.Time `json:"lastSync"`
	Error    string    `json:"error,omitempty"`
}

// Follower pulls snapshots from the primary.
type Follower struct {
	Primary string // the primary's sign-in address, e.g. https://login.example.com
	Token   string
	// Address, if set, is where to reach the primary (host:port), when DNS
	// for its name points at several servers.
	Address string
	DataDir string
	Store   *store.Store
	Log     *slog.Logger
	// Applied is called after a snapshot changed something.
	Applied func(certsChanged bool)
	// HTTPClient overrides the client (tests).
	HTTPClient *http.Client

	// CertDir is the primary's certificate folder, from the last snapshot.
	CertDir string

	mu       sync.Mutex
	status   Status
	lastHash string
	certHash string
}

// Status reports the last sync.
func (f *Follower) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.status
	s.Primary = f.Primary
	return s
}

func (f *Follower) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if f.Address != "" {
		addr := f.Address
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		}
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}
}

// Fetch downloads a snapshot.
func (f *Follower) Fetch(ctx context.Context) (*Payload, error) {
	if !strings.HasPrefix(f.Primary, "https://") {
		return nil, errors.New("--follow must start with https://")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(f.Primary, "/")+Path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.Token)
	if f.lastHash != "" {
		req.Header.Set("If-None-Match", f.lastHash)
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, nil
	case http.StatusUnauthorized:
		return nil, errors.New("the primary refused this server's token")
	default:
		return nil, fmt.Errorf("the primary answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPayload+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPayload {
		return nil, errors.New("snapshot too large")
	}
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("the primary runs a newer RyProx (snapshot version %d); update this server", p.Version)
	}
	return &p, nil
}

// WriteSecret stores the primary's secret key. Call before opening the
// secrets box.
func (f *Follower) WriteSecret(p *Payload) error {
	key, err := base64.StdEncoding.DecodeString(p.SecretKey)
	if err != nil || len(key) == 0 {
		return errors.New("snapshot has no secret key")
	}
	path := filepath.Join(f.DataDir, "secret.key")
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, key) { //nolint:gosec // our data directory
		return nil
	}
	return os.WriteFile(path, key, 0o600)
}

// Apply writes a snapshot locally.
func (f *Follower) Apply(ctx context.Context, p *Payload) error {
	if err := f.WriteSecret(p); err != nil {
		return err
	}
	if err := f.Store.ImportConfig(ctx, p.Config); err != nil {
		return err
	}
	certsJSON, _ := json.Marshal(p.Certs)
	certHash := fmt.Sprintf("%x", sha(certsJSON))
	certsChanged := certHash != f.certHash
	if certsChanged {
		certDir := filepath.Join(f.DataDir, "certs")
		for rel, b64 := range p.Certs {
			clean := filepath.Clean(filepath.FromSlash(rel))
			if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
				continue // never write outside certs/
			}
			b, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				continue
			}
			dst := filepath.Join(certDir, clean)
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(dst, b, 0o600); err != nil {
				return err
			}
		}
		f.certHash = certHash
	}
	f.lastHash = p.Hash
	f.CertDir = p.CertDir
	// Remembered for starting while the primary is unreachable.
	_ = os.WriteFile(filepath.Join(f.DataDir, "certs", ".primary-folder"), []byte(p.CertDir), 0o600)
	if f.Applied != nil {
		f.Applied(certsChanged)
	}
	return nil
}

// LoadCertDir restores the primary's certificate folder saved by the last sync.
func (f *Follower) LoadCertDir() {
	if f.CertDir == "" {
		if b, err := os.ReadFile(filepath.Join(f.DataDir, "certs", ".primary-folder")); err == nil { //nolint:gosec // our data directory
			f.CertDir = strings.TrimSpace(string(b))
		}
	}
}

// Sync fetches and applies one snapshot.
func (f *Follower) Sync(ctx context.Context) error {
	p, err := f.Fetch(ctx)
	if err == nil && p != nil {
		err = f.Apply(ctx, p)
	}
	f.mu.Lock()
	if err != nil {
		f.status.Error = err.Error()
	} else {
		f.status.Error, f.status.LastSync = "", time.Now()
	}
	f.mu.Unlock()
	return err
}

// Run syncs until ctx ends.
func (f *Follower) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(Interval):
		}
		if err := f.Sync(ctx); err != nil && ctx.Err() == nil {
			f.Log.Warn("sync from primary failed; still serving the last configuration", "err", err)
		}
	}
}

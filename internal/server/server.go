// SPDX-License-Identifier: AGPL-3.0-only

// Package server starts RyProx: the database, proxy engine, certificate
// manager, admin dashboard and the network listeners.
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rylanq/ryprox/internal/api"
	"github.com/rylanq/ryprox/internal/certs"
	"github.com/rylanq/ryprox/internal/cluster"
	"github.com/rylanq/ryprox/internal/console"
	"github.com/rylanq/ryprox/internal/crowdsec"
	"github.com/rylanq/ryprox/internal/health"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/secrets"
	"github.com/rylanq/ryprox/internal/store"
	"github.com/rylanq/ryprox/internal/tunnel"
)

// Options configure a RyProx instance. Everything else is set in the UI.
type Options struct {
	DataDir   string // database, secret key and certificates
	HTTPAddr  string // public HTTP listener, e.g. ":80"
	HTTPSAddr string // public HTTPS listener, e.g. ":443"
	AdminAddr string // admin dashboard listener, e.g. "127.0.0.1:8081"; "" to disable
	// Advanced: get certificates from another ACME server instead of Let's Encrypt.
	ACMEDirectory string
	ACMECAFile    string
	Guacd         string // default guacd address (the dashboard setting wins)
	RelayHost     string // how guacd reaches RyProx, for desktops on a site
	Follow        string // the primary's sign-in address, to run as a follower
	FollowToken   string
	FollowAddress string // optional host:port of the primary's HTTPS listener
	Log           *slog.Logger
	UI            fs.FS
	// Ready, if set, is called once all listeners are open.
	Ready func(adminURL, setupCode string)
}

// Run starts RyProx and blocks until ctx is cancelled.
func Run(ctx context.Context, o Options) error {
	log := o.Log
	if err := os.MkdirAll(o.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	st, err := store.Open(ctx, filepath.Join(o.DataDir, "ryprox.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	// A follower first copies the primary's configuration and secret key.
	var follower *cluster.Follower
	if o.Follow != "" {
		follower = &cluster.Follower{Primary: o.Follow, Token: o.FollowToken, Address: o.FollowAddress, DataDir: o.DataDir, Store: st, Log: log}
		for {
			err := follower.Sync(ctx)
			if err == nil {
				break
			}
			log.Warn("waiting for the primary", "primary", o.Follow, "err", err)
			if _, statErr := os.Stat(filepath.Join(o.DataDir, "secret.key")); statErr == nil {
				log.Warn("starting with the last configuration copied from the primary")
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
		log.Info("following the primary", "primary", o.Follow)
	}

	box, err := secrets.LoadOrCreate(filepath.Join(o.DataDir, "secret.key"))
	if err != nil {
		return fmt.Errorf("load secret key: %w", err)
	}

	engine := proxy.NewEngine(log)
	defer engine.Close()
	routes, err := st.ListRoutes(ctx)
	if err != nil {
		return err
	}
	if err := engine.Apply(routes); err != nil {
		return fmt.Errorf("saved routes are invalid: %w", err)
	}

	bouncer := crowdsec.New(log)
	defer bouncer.Close()
	adm := &api.Server{Store: st, Engine: engine, Box: box, Log: log, UI: o.UI, HTTPSPort: portOf(o.HTTPSAddr), CrowdSec: bouncer,
		DataDir: o.DataDir, Follower: follower}
	cm := certs.New(filepath.Join(o.DataDir, "certs"), func(host string) bool {
		if set := adm.Settings(); host != "" && (host == set.AdminHostname || host == set.AuthHostname) {
			return true
		}
		return engine.HasHost(host)
	}, log)
	adm.Certs = cm
	if follower != nil {
		cm.SetFollower(true)
		follower.Applied = func(certsChanged bool) {
			if err := adm.Reload(context.Background()); err != nil {
				log.Error("could not apply the primary's configuration", "err", err)
			}
			cm.UseSubdir(follower.CertDir)
			if certsChanged {
				cm.Reload()
			}
		}
		follower.LoadCertDir()
		cm.UseSubdir(follower.CertDir)
		go follower.Run(ctx)
	}
	engine.SetGate(adm) // private routes check every request against the access lists
	adm.Console = &console.Service{Store: st, Box: box, Log: log, UI: o.UI, DefaultGuacd: o.Guacd, RelayHost: o.RelayHost,
		Audit: func(r *http.Request, actor, action, detail string) { adm.Audit(r, actor, action, detail) }}
	engine.SetConsole(adm.Console)
	hub := tunnel.NewHub(log)
	adm.Tunnels = hub
	engine.SetTunnels(hub)
	adm.Console.Dial = engine.DialTarget
	if o.ACMEDirectory != "" {
		if err := cm.UseCustomServer(o.ACMEDirectory, o.ACMECAFile); err != nil {
			return err
		}
		log.Info("using a custom ACME server for certificates", "directory", o.ACMEDirectory)
	}
	setupCode, err := api.New(ctx, adm)
	if err != nil {
		return err
	}
	cm.Configure(adm.Settings())

	adminHandler := adm.Handler()
	signInHandler := adm.SignInHandler()
	httpsPort := portOf(o.HTTPSAddr)

	// Visitors banned by CrowdSec are turned away before anything else.
	deny := func(w http.ResponseWriter) {
		proxy.WritePage(w, http.StatusForbidden, "Access blocked", "Your address has been blocked because of suspicious activity.")
	}

	// Public HTTP: Let's Encrypt challenges, HTTPS redirects, and plain-HTTP routes.
	var httpHandler http.Handler = cm.HTTPHandler(bouncer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := proxy.NormalizeHost(r.Host)
		set := adm.Settings()
		ownDomain := host != "" && (host == set.AdminHostname || host == set.AuthHostname)
		if ownDomain || (cm.Enabled() && engine.IsHTTPSRedirect(host)) {
			redirectHTTPS(w, r, host, httpsPort)
			return
		}
		engine.ServeHTTP(w, r)
	}), deny))

	// Public HTTPS: RyProx's own domains (dashboard, sign-in), else routes.
	httpsHandler := bouncer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := proxy.NormalizeHost(r.Host)
		set := adm.Settings()
		switch {
		case host != "" && host == set.AdminHostname:
			adminHandler.ServeHTTP(w, r)
		case host != "" && host == set.AuthHostname:
			signInHandler.ServeHTTP(w, r)
		default:
			engine.ServeHTTP(w, r)
		}
	}), deny)

	mux := http.NewServeMux()
	mux.Handle("/healthz", health.Handler())
	mux.Handle("/", adminHandler)

	type srv struct {
		name string
		s    *http.Server
		tls  bool
	}
	var servers []srv
	if o.AdminAddr != "" {
		servers = append(servers, srv{"admin", adminServer(o.AdminAddr, mux), false})
	}
	if o.HTTPAddr != "" {
		servers = append(servers, srv{"http", proxyServer(o.HTTPAddr, httpHandler, log), false})
	}
	if o.HTTPSAddr != "" {
		s := proxyServer(o.HTTPSAddr, httpsHandler, log)
		s.TLSConfig = cm.TLSConfig()
		servers = append(servers, srv{"https", s, true})
	}

	// Open every listener first, so a port problem is reported straight away.
	errCh := make(chan error, len(servers))
	listeners := make([]net.Listener, len(servers))
	for i, x := range servers {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", x.s.Addr)
		if err != nil {
			for _, l := range listeners[:i] {
				_ = l.Close()
			}
			return fmt.Errorf("%s listener on %s: %w", x.name, x.s.Addr, err)
		}
		listeners[i] = ln
	}
	for i, x := range servers {
		go func() {
			var err error
			if x.tls {
				err = x.s.ServeTLS(listeners[i], "", "")
			} else {
				err = x.s.Serve(listeners[i])
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s listener: %w", x.name, err)
			}
		}()
		log.Info("listening", "listener", x.name, "addr", listeners[i].Addr().String())
	}

	if follower != nil {
		// The primary gets the certificates; Let's Encrypt may check any
		// server behind the name, so pass its challenges on to the primary.
		httpHandler = forwardChallenges(httpHandler, o.Follow, o.FollowAddress)
	}

	// Request certificates for everything up front.
	if cm.Enabled() && follower == nil {
		if h := adm.Settings().AdminHostname; h != "" {
			cm.Obtain(h)
		}
		if h := adm.Settings().AuthHostname; h != "" {
			cm.Obtain(h)
		}
		for _, h := range engine.Hostnames() {
			cm.Obtain(h)
		}
	}

	if o.Ready != nil {
		adminURL := ""
		if o.AdminAddr != "" {
			adminURL = "http://" + displayAddr(listeners[0].Addr().String())
		}
		o.Ready(adminURL, setupCode)
	}

	// Housekeeping.
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err := <-errCh:
			runErr = err
			break loop
		case <-tick.C:
			adm.Cleanup(ctx)
		}
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, x := range servers {
		_ = x.s.Shutdown(shutdownCtx)
	}
	return runErr
}

// adminServer has strict timeouts: the dashboard never needs long requests.
func adminServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

// proxyServer allows long-running requests (uploads, downloads, websockets)
// but still limits how slowly headers may arrive.
func proxyServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
}

func redirectHTTPS(w http.ResponseWriter, r *http.Request, host, port string) {
	target := "https://" + host
	if port != "" && port != "443" {
		target += ":" + port
	}
	// host is always a configured route or admin domain (checked by the caller),
	// so this can't be used to redirect visitors to an arbitrary site.
	http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusPermanentRedirect) //nolint:gosec // see above
}

func portOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return p
}

func displayAddr(a string) string {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return a
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

// forwardChallenges sends ACME HTTP-01 challenges to the primary server.
func forwardChallenges(next http.Handler, primaryURL, primaryAddr string) http.Handler {
	host := ""
	if u, err := url.Parse(primaryURL); err == nil {
		host = u.Hostname()
	}
	if primaryAddr != "" {
		if h, _, err := net.SplitHostPort(primaryAddr); err == nil {
			host = h
		}
	}
	target := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, "80")}
	rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = pr.In.Host
	}, Transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 10 * time.Second}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") && r.Header.Get("X-RyProx-Forwarded") == "" {
			r.Header.Set("X-RyProx-Forwarded", "1") // never loop between servers
			rp.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

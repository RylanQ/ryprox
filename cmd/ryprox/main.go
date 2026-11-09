// SPDX-License-Identifier: AGPL-3.0-only

// Command ryprox is the RyProx server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rylanq/ryprox/internal/config"
	"github.com/rylanq/ryprox/internal/server"
	"github.com/rylanq/ryprox/internal/store"
	"github.com/rylanq/ryprox/internal/version"
	"github.com/rylanq/ryprox/internal/web"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run is separated from main so it can be tested.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errors.New("no command given")
	}
	switch args[0] {
	case "version", "--version", "-v":
		_, err := fmt.Fprintln(stdout, version.Get())
		return err
	case "serve":
		return serve(args[1:], stdout, stderr)
	case "init":
		return initCmd(args[1:], stdout, stderr)
	case "reset-admin":
		return resetAdmin(args[1:], stdout, stderr)
	case "healthcheck":
		return healthcheck()
	case "help", "--help", "-h":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `RyProx: UI-first reverse proxy

Commands:
  serve         Start RyProx
  init          Pre-configure HTTPS and the dashboard domain (used by the installer)
  reset-admin   Remove the admin account so setup runs again (if you're locked out)
  healthcheck   Exit 0 if RyProx is answering (used by Docker)
  version       Print version information
  help          Show this help

Run "ryprox serve -h" to see its options.
`)
}

// env returns the environment variable's value, or def.
func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

func serve(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", env("RYPROX_DATA", "./data"), "directory for the database, keys and certificates (env RYPROX_DATA)")
	httpAddr := fs.String("http", env("RYPROX_HTTP", ":80"), "public HTTP address (env RYPROX_HTTP)")
	httpsAddr := fs.String("https", env("RYPROX_HTTPS", ":443"), "public HTTPS address (env RYPROX_HTTPS)")
	adminAddr := fs.String("admin", env("RYPROX_ADMIN", "127.0.0.1:8081"), "admin dashboard address; keep it on 127.0.0.1 unless you know why (env RYPROX_ADMIN)")
	acmeDir := fs.String("acme-directory", env("RYPROX_ACME_DIRECTORY", ""), "advanced: ACME server URL to use instead of Let's Encrypt, e.g. a private step-ca (env RYPROX_ACME_DIRECTORY)")
	acmeCA := fs.String("acme-ca", env("RYPROX_ACME_CA", ""), "advanced: PEM file of root certificates for that ACME server (env RYPROX_ACME_CA)")
	logLevel := fs.String("log-level", env("RYPROX_LOG_LEVEL", "info"), "debug, info, warn or error (env RYPROX_LOG_LEVEL)")
	logFormat := fs.String("log-format", env("RYPROX_LOG_FORMAT", "text"), "text or json (env RYPROX_LOG_FORMAT)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("invalid log level %q", *logLevel)
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler = slog.NewTextHandler(stderr, opts)
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(stderr, opts)
	}
	log := slog.New(handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("starting RyProx", "version", version.Version, "data", *data)
	return server.Run(ctx, server.Options{
		DataDir:       *data,
		HTTPAddr:      *httpAddr,
		HTTPSAddr:     *httpsAddr,
		AdminAddr:     *adminAddr,
		ACMEDirectory: *acmeDir,
		ACMECAFile:    *acmeCA,
		Log:           log,
		UI:            web.Static(),
		Ready: func(adminURL, setupCode string) {
			printBanner(stdout, adminURL, setupCode)
		},
	})
}

func printBanner(w io.Writer, adminURL, setupCode string) {
	line := strings.Repeat("─", 60)
	_, _ = fmt.Fprintln(w, line)
	_, _ = fmt.Fprintf(w, "  RyProx %s is running\n", version.Version)
	if adminURL != "" {
		_, _ = fmt.Fprintf(w, "  Admin dashboard: %s\n", adminURL)
	}
	if setupCode != "" {
		_, _ = fmt.Fprintf(w, "\n  First-time setup code:  %s\n", setupCode)
		_, _ = fmt.Fprintln(w, "  Enter it in the dashboard to create your admin account.")
	}
	_, _ = fmt.Fprintln(w, line)
}

func resetAdmin(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("reset-admin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", env("RYPROX_DATA", "./data"), "data directory (env RYPROX_DATA)")
	yes := fs.Bool("yes", false, "confirm")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*yes {
		_, _ = fmt.Fprintln(stdout, "This removes all admin accounts. Routes, settings and other people's accounts are kept.")
		_, _ = fmt.Fprintln(stdout, "Run again with --yes to confirm, then restart RyProx and use the new setup code.")
		return nil
	}
	path := filepath.Join(*data, "ryprox.db")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no database at %s: %w", path, err)
	}
	st, err := store.Open(context.Background(), path)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := st.DeleteAllAdmins(context.Background()); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "Admin accounts removed. Restart RyProx; it will print a new setup code.")
	return nil
}

// healthcheck asks the local admin listener whether RyProx is up.
func healthcheck() error {
	addr := env("RYPROX_ADMIN", "127.0.0.1:8081")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}

// initCmd writes HTTPS settings before RyProx first starts, so the
// installer can set everything up in one go. It can be re-run safely.
func initCmd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", env("RYPROX_DATA", "./data"), "data directory (env RYPROX_DATA)")
	email := fs.String("acme-email", "", "email for Let's Encrypt; turns on automatic HTTPS")
	staging := fs.Bool("acme-staging", false, "use Let's Encrypt test certificates")
	adminDomain := fs.String("admin-domain", "", "serve the dashboard on this domain over HTTPS (needs --acme-email)")
	authDomain := fs.String("auth-domain", "", "where people sign in to private sites (needs --acme-email)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st := store.Settings{TLSMode: store.TLSModeOff, AdminHostname: *adminDomain, AuthHostname: *authDomain}
	if *email != "" {
		st.TLSMode, st.ACMEEmail, st.ACMEStaging = store.TLSModeACME, *email, *staging
	}
	if err := config.NormalizeSettings(&st); err != nil {
		return err
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		return err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(*data, "ryprox.db"))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if err := db.SaveSettings(ctx, st); err != nil {
		return err
	}
	_ = db.AddAudit(ctx, store.AuditEntry{Actor: "installer", Action: "settings.update", Detail: "set up from the command line"})
	mode := "HTTP only"
	if st.TLSMode == store.TLSModeACME {
		mode = "automatic HTTPS"
		if st.ACMEStaging {
			mode += " with test certificates"
		}
	}
	_, _ = fmt.Fprintf(stdout, "Saved: %s", mode)
	if st.AuthHostname != "" {
		_, _ = fmt.Fprintf(stdout, ", sign-in at https://%s", st.AuthHostname)
	}
	if st.AdminHostname != "" {
		_, _ = fmt.Fprintf(stdout, ", dashboard at https://%s", st.AdminHostname)
	}
	_, _ = fmt.Fprintln(stdout)
	return nil
}

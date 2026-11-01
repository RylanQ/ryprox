// SPDX-License-Identifier: AGPL-3.0-only

// Command ryprox is the RyProx server.
//
// Usage:
//
//	ryprox version              print version information
//	ryprox serve [-addr ADDR]   start the server (currently only /healthz)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rylanq/ryprox/internal/health"
	"github.com/rylanq/ryprox/internal/version"
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
		return serve(args[1:], stderr)
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
  version   Print version information
  serve     Start the server
  help      Show this help
`)
}

func serve(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	// Listen on localhost only by default: nothing should be exposed to the
	// network unless the operator chooses to.
	addr := fs.String("addr", "127.0.0.1:8080", "address to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))

	mux := http.NewServeMux()
	mux.Handle("/healthz", health.Handler())

	srv := newServer(*addr, mux)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting RyProx", "addr", *addr, "version", version.Version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// newServer returns an http.Server with safe timeouts. Without these, a
// client can hold connections open forever (e.g. a Slowloris attack).
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KiB
	}
}

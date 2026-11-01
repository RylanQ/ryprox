// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestVersionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"version"}, &out, &errOut); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out.String(), "RyProx ") {
		t.Fatalf("got %q", out.String())
	}
}

func TestNoCommandIsAnError(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(nil, &out, &errOut); err == nil {
		t.Fatal("expected an error")
	}
}

func TestUnknownCommandIsAnError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"frobnicate"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("got %v", err)
	}
}

func TestServerHasTimeouts(t *testing.T) {
	srv := newServer("127.0.0.1:0", nil)
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("all timeouts must be set: %+v", srv)
	}
	if srv.ReadHeaderTimeout > 10*time.Second {
		t.Fatalf("ReadHeaderTimeout too long: %v", srv.ReadHeaderTimeout)
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 1<<20 {
		t.Fatalf("MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
}

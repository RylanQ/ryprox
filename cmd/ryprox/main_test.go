// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
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

func TestInitCommand(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	err := run([]string{"init", "--data", dir, "--acme-email", "me@example.com", "--acme-staging",
		"--admin-domain", "Admin.Example.com"}, &out, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "https://admin.example.com") {
		t.Fatalf("output: %q", out.String())
	}
	// Invalid combinations are refused before anything is written.
	if err := run([]string{"init", "--data", dir, "--admin-domain", "admin.example.com"}, &out, &errOut); err == nil {
		t.Fatal("admin domain without HTTPS accepted")
	}
	if err := run([]string{"init", "--data", dir, "--acme-email", "not-an-email"}, &out, &errOut); err == nil {
		t.Fatal("bad email accepted")
	}
}

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

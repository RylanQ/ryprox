// SPDX-License-Identifier: AGPL-3.0-only

package version

import (
	"strings"
	"testing"
)

func TestGetUsesBuildVariables(t *testing.T) {
	oldV, oldC, oldD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = oldV, oldC, oldD })

	Version, Commit, Date = "v1.2.3", "abc1234", "2026-11-01"
	info := Get()

	if info.Version != "v1.2.3" || info.Commit != "abc1234" || info.Date != "2026-11-01" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if info.GoVersion == "" || info.Platform == "" {
		t.Fatalf("runtime fields should be filled: %+v", info)
	}
}

func TestStringContainsVersion(t *testing.T) {
	s := Info{Version: "v9.9.9", Commit: "c", Date: "d", GoVersion: "go", Platform: "p"}.String()
	if !strings.HasPrefix(s, "RyProx v9.9.9") {
		t.Fatalf("got %q", s)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

// Package version reports which build of RyProx is running.
//
// The variables are set at build time by the Makefile using -ldflags, e.g.
//
//	go build -ldflags "-X github.com/rylanq/ryprox/internal/version.Version=v0.1.0"
package version

import (
	"fmt"
	"runtime"
)

// Set at build time. The defaults are what a plain `go build` produces.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Info is a snapshot of the build information.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Get returns the build information for this binary.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String returns a one-line, human-readable version description.
func (i Info) String() string {
	return fmt.Sprintf("RyProx %s (commit %s, built %s, %s, %s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.Platform)
}

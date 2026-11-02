// SPDX-License-Identifier: AGPL-3.0-only

// Package web holds the admin dashboard's files, built into the binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// Static returns the dashboard files.
func Static() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

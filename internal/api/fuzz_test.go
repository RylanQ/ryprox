// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzSafeRedirectPath(f *testing.F) {
	for _, s := range []string{"/", "/a?b=1", "//evil.com", "/\\evil.com", "/.ryprox/logout", "/a/../.ryprox/x", "https://evil.com", "/%2e%2e/%2f/evil.com", "/a//b", "/\t/evil.com", "/;/evil.com", "/%5cevil.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := safeRedirectPath(in)
		if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") || strings.ContainsAny(out, "\\\r\n\t\x00") {
			t.Fatalf("%q → %q", in, out)
		}
		u, err := url.Parse(out)
		if err != nil || u.Host != "" || u.Scheme != "" {
			t.Fatalf("%q → %q parses as %+v %v", in, out, u, err)
		}
		// A browser resolving it against a site must stay on that site.
		base, _ := url.Parse("https://site.example/")
		if abs := base.ResolveReference(u); abs.Host != "site.example" || abs.Scheme != "https" {
			t.Fatalf("%q → %q leaves the site: %s", in, out, abs)
		}
		if strings.HasPrefix(u.Path, "/.ryprox/") || u.Path == "/.ryprox" {
			t.Fatalf("%q → %q reaches the portal", in, out)
		}
	})
}

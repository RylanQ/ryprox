// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"net/http"
	"strings"
	"testing"
)

func FuzzStripRyproxCookies(f *testing.F) {
	for _, s := range []string{"a=b; __Host-ryprox-access=tok", "__host-RYPROX=1;x=y", "ryprox-state=1", " ryprox = 1 ; b=2", "a=\"x; ryprox=2\"", "RyProx-Access=1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if strings.ContainsAny(in, "\r\n") {
			return
		}
		h := http.Header{"Cookie": {in}}
		stripRyproxCookies(h)
		r := &http.Request{Header: h}
		for _, c := range r.Cookies() {
			if IsRyproxCookie(c.Name) {
				t.Fatalf("%q left %q behind (header now %q)", in, c.Name, h.Get("Cookie"))
			}
		}
		for _, part := range strings.Split(h.Get("Cookie"), ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if IsRyproxCookie(name) {
				t.Fatalf("%q left %q behind", in, name)
			}
		}
	})
}

func FuzzStripUnsafeHeaders(f *testing.F) {
	f.Add("X-Ryprox-User", "x")
	f.Add("x_ryprox_user", "x")
	f.Add("X-RYPROX-token", "x")
	f.Fuzz(func(t *testing.T, name, value string) {
		h := http.Header{name: {value}}
		stripUnsafeHeaders(h)
		for k := range h {
			norm := strings.ToLower(strings.ReplaceAll(k, "_", "-"))
			if strings.HasPrefix(norm, "x-ryprox-") {
				t.Fatalf("%q survived", k)
			}
		}
	})
}

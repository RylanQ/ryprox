// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"testing"

	"github.com/rylanq/ryprox/internal/store"
)

func TestNormalizeHostname(t *testing.T) {
	good := map[string]string{
		"App.Example.com":   "app.example.com",
		" app.example.com.": "app.example.com",
		"localhost":         "localhost",
		"xn--bcher-kva.de":  "xn--bcher-kva.de",
		"a-b.c":             "a-b.c",
	}
	for in, want := range good {
		got, err := NormalizeHostname("h", in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	bad := []string{"", "https://app.example.com", "app.example.com/x", "app.example.com:443",
		"*.example.com", "10.0.0.1", "::1", "-a.com", "a-.com", "a..com", "bücher.de", "a com",
		"a.com?x", "a.com#x"}
	for _, in := range bad {
		if _, err := NormalizeHostname("h", in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestNormalizeTargetURL(t *testing.T) {
	good := map[string]string{
		"http://10.0.0.5:8080":   "http://10.0.0.5:8080",
		"HTTP://Server.LAN:80/":  "http://server.lan:80",
		"https://192.168.1.2":    "https://192.168.1.2",
		"http://[::1]:3000":      "http://[::1]:3000",
		" http://localhost:9000": "http://localhost:9000",
	}
	for in, want := range good {
		got, err := NormalizeTargetURL("t", in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	bad := []string{"", "10.0.0.5:8080", "ftp://x", "http://", "http://user:pw@x",
		"http://x?y=1", "http://x/#f", "http://x/app", "http://x:0", "http://x:70000", "javascript:alert(1)"}
	for _, in := range bad {
		if _, err := NormalizeTargetURL("t", in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func validRoute() store.Route {
	return store.Route{Hostname: "App.example.com", Config: store.RouteConfig{Targets: []store.Target{{URL: "http://10.0.0.1:80"}}}}
}

func TestNormalizeRouteDefaults(t *testing.T) {
	r := validRoute()
	if err := NormalizeRoute(&r); err != nil {
		t.Fatal(err)
	}
	if r.Hostname != "app.example.com" || r.Config.LoadBalancing != "round_robin" ||
		r.Config.HealthCheck.Path != "/" || r.Config.HealthCheck.IntervalSeconds != 15 {
		t.Fatalf("defaults not applied: %+v", r)
	}
}

func TestNormalizeRouteRejects(t *testing.T) {
	cases := map[string]func(*store.Route){
		"no targets": func(r *store.Route) { r.Config.Targets = nil },
		"duplicate target": func(r *store.Route) {
			r.Config.Targets = append(r.Config.Targets, store.Target{URL: "http://10.0.0.1:80/"})
		},
		"bad lb": func(r *store.Route) { r.Config.LoadBalancing = "random" },
		"header newline": func(r *store.Route) {
			r.Config.RequestHeaders = []store.HeaderRule{{Action: "set", Name: "X-A", Value: "a\r\nX-Evil: 1"}}
		},
		"forbidden header": func(r *store.Route) {
			r.Config.RequestHeaders = []store.HeaderRule{{Action: "set", Name: "Host", Value: "x"}}
		},
		"bad header name": func(r *store.Route) {
			r.Config.ResponseHeaders = []store.HeaderRule{{Action: "set", Name: "X A", Value: "x"}}
		},
		"bad action":        func(r *store.Route) { r.Config.ResponseHeaders = []store.HeaderRule{{Action: "add", Name: "X-A"}} },
		"health path":       func(r *store.Route) { r.Config.HealthCheck.Path = "health" },
		"health path //":    func(r *store.Route) { r.Config.HealthCheck.Path = "//evil.com" },
		"health interval":   func(r *store.Route) { r.Config.HealthCheck.IntervalSeconds = 1 },
		"too many targets":  func(r *store.Route) { r.Config.Targets = make([]store.Target, MaxTargets+1) },
		"hostname has path": func(r *store.Route) { r.Hostname = "a.com/b" },
	}
	for name, mutate := range cases {
		r := validRoute()
		mutate(&r)
		err := NormalizeRoute(&r)
		var fe *FieldError
		if !errors.As(err, &fe) {
			t.Errorf("%s: want FieldError, got %v", name, err)
		}
	}
}

func TestNormalizeSettings(t *testing.T) {
	s := store.Settings{TLSMode: store.TLSModeACME, ACMEEmail: " me@example.com ", AdminHostname: "Admin.Example.com"}
	if err := NormalizeSettings(&s); err != nil {
		t.Fatal(err)
	}
	if s.ACMEEmail != "me@example.com" || s.AdminHostname != "admin.example.com" {
		t.Fatalf("got %+v", s)
	}
	for _, bad := range []store.Settings{
		{TLSMode: store.TLSModeACME},
		{TLSMode: store.TLSModeACME, ACMEEmail: "Me <me@example.com>"},
		{TLSMode: "magic"},
		{TLSMode: store.TLSModeACME, ACMEEmail: "a@b.co", AdminHostname: "https://x"},
		{TLSMode: store.TLSModeOff, AdminHostname: "admin.example.com"},
	} {
		if err := NormalizeSettings(&bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := CheckRoutes([]store.Route{{Hostname: "admin.example.com"}}, "admin.example.com"); err == nil {
		t.Error("route on admin hostname accepted")
	}
}

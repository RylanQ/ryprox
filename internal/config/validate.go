// SPDX-License-Identifier: AGPL-3.0-only

// Package config validates and normalises everything an admin can enter,
// so that only safe, working configuration ever reaches the database.
package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"

	"github.com/rylanq/ryprox/internal/store"
)

// FieldError points at the form field that is wrong.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Message }

func fieldErr(field, format string, a ...any) error {
	return &FieldError{Field: field, Message: fmt.Sprintf(format, a...)}
}

// Limits.
const (
	MaxTargets     = 20
	MaxHeaderRules = 50
)

// NormalizeHostname lower-cases and checks a hostname like "app.example.com".
// Ports, schemes, paths, IP addresses and wildcards are rejected.
func NormalizeHostname(field, h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	switch {
	case h == "":
		return "", fieldErr(field, "enter a domain name, like app.example.com")
	case strings.Contains(h, "://"):
		return "", fieldErr(field, "enter just the domain, without http:// or https://")
	case strings.ContainsAny(h, "/?#"):
		return "", fieldErr(field, "enter just the domain, without a path")
	case strings.Contains(h, "*"):
		return "", fieldErr(field, "wildcard domains are not supported yet")
	case strings.Contains(h, ":"):
		return "", fieldErr(field, "enter the domain without a port")
	case net.ParseIP(h) != nil:
		return "", fieldErr(field, "enter a domain name, not an IP address")
	case len(h) > 253:
		return "", fieldErr(field, "domain is too long")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return "", fieldErr(field, "%q is not a valid domain name", h)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fieldErr(field, "domain parts can't start or end with a hyphen")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fieldErr(field, "domain contains an invalid character %q (use punycode for international names)", c)
			}
		}
	}
	return h, nil
}

// NormalizeTargetURL checks a backend address like "http://10.0.0.5:8080".
func NormalizeTargetURL(field, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fieldErr(field, "enter the address of the service, like http://192.168.1.10:8080")
	}
	if !strings.Contains(raw, "://") {
		return "", fieldErr(field, "start the address with http:// or https://")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fieldErr(field, "not a valid address")
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return "", fieldErr(field, "address must start with http:// or https://")
	case u.Host == "" || u.Hostname() == "":
		return "", fieldErr(field, "address is missing a host")
	case u.User != nil:
		return "", fieldErr(field, "addresses with usernames or passwords are not allowed; use a header rule instead")
	case u.RawQuery != "" || u.Fragment != "":
		return "", fieldErr(field, "address can't contain ? or #")
	case u.Path != "" && u.Path != "/":
		return "", fieldErr(field, "sub-paths on the backend aren't supported yet; use just the host and port")
	}
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 1 || n > 65535 {
			return "", fieldErr(field, "port must be between 1 and 65535")
		}
	}
	u.Path = ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

// Headers that would break the HTTP protocol or bypass RyProx if changed.
var forbiddenHeaders = map[string]bool{
	"connection": true, "content-length": true, "transfer-encoding": true, "te": true,
	"trailer": true, "upgrade": true, "keep-alive": true, "proxy-connection": true,
	"host": true, "proxy-authorization": true, "proxy-authenticate": true,
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func normalizeHeaderRules(field string, rules []store.HeaderRule) ([]store.HeaderRule, error) {
	if len(rules) > MaxHeaderRules {
		return nil, fieldErr(field, "at most %d header rules", MaxHeaderRules)
	}
	out := make([]store.HeaderRule, 0, len(rules))
	for i, r := range rules {
		f := fmt.Sprintf("%s.%d", field, i)
		r.Name = strings.TrimSpace(r.Name)
		if !validHeaderName(r.Name) {
			return nil, fieldErr(f, "%q is not a valid header name", r.Name)
		}
		if forbiddenHeaders[strings.ToLower(r.Name)] {
			return nil, fieldErr(f, "the %s header is managed by RyProx and can't be changed", r.Name)
		}
		switch r.Action {
		case "set":
			if strings.ContainsAny(r.Value, "\r\n\x00") || len(r.Value) > 4096 {
				return nil, fieldErr(f, "header value contains invalid characters or is too long")
			}
		case "remove":
			r.Value = ""
		default:
			return nil, fieldErr(f, "action must be set or remove")
		}
		out = append(out, r)
	}
	return out, nil
}

// NormalizeRoute validates a route in place and fills in defaults.
func NormalizeRoute(r *store.Route) error {
	h, err := NormalizeHostname("hostname", r.Hostname)
	if err != nil {
		return err
	}
	r.Hostname = h

	c := &r.Config
	if len(c.Targets) == 0 {
		return fieldErr("targets", "add at least one target")
	}
	if len(c.Targets) > MaxTargets {
		return fieldErr("targets", "at most %d targets", MaxTargets)
	}
	seen := map[string]bool{}
	for i := range c.Targets {
		u, err := NormalizeTargetURL(fmt.Sprintf("targets.%d", i), c.Targets[i].URL)
		if err != nil {
			return err
		}
		if seen[u] {
			return fieldErr(fmt.Sprintf("targets.%d", i), "this target is listed twice")
		}
		seen[u] = true
		c.Targets[i].URL = u
	}
	switch c.LoadBalancing {
	case "":
		c.LoadBalancing = "round_robin"
	case "round_robin", "failover":
	default:
		return fieldErr("loadBalancing", "choose round robin or failover")
	}
	if c.RequestHeaders, err = normalizeHeaderRules("requestHeaders", c.RequestHeaders); err != nil {
		return err
	}
	if c.ResponseHeaders, err = normalizeHeaderRules("responseHeaders", c.ResponseHeaders); err != nil {
		return err
	}
	hc := &c.HealthCheck
	if hc.Path == "" {
		hc.Path = "/"
	}
	if !strings.HasPrefix(hc.Path, "/") || strings.HasPrefix(hc.Path, "//") || strings.ContainsAny(hc.Path, " \r\n#") || len(hc.Path) > 512 {
		return fieldErr("healthCheck.path", "path must start with / (for example /health)")
	}
	if hc.IntervalSeconds == 0 {
		hc.IntervalSeconds = 15
	}
	if hc.IntervalSeconds < 5 || hc.IntervalSeconds > 3600 {
		return fieldErr("healthCheck.intervalSeconds", "interval must be between 5 and 3600 seconds")
	}
	return nil
}

// NormalizeSettings validates instance settings.
func NormalizeSettings(s *store.Settings) error {
	switch s.TLSMode {
	case store.TLSModeACME:
		s.ACMEEmail = strings.TrimSpace(s.ACMEEmail)
		if s.ACMEEmail == "" {
			return fieldErr("acmeEmail", "Let's Encrypt needs an email address for expiry warnings")
		}
		a, err := mail.ParseAddress(s.ACMEEmail)
		if err != nil || a.Address != s.ACMEEmail {
			return fieldErr("acmeEmail", "enter a valid email address")
		}
	case store.TLSModeOff:
	default:
		return fieldErr("tlsMode", "choose automatic HTTPS or HTTP only")
	}
	if s.AdminHostname != "" {
		if s.TLSMode != store.TLSModeACME {
			return fieldErr("adminHostname", "the admin dashboard can only be put on a domain when automatic HTTPS is on, so your password is never sent unencrypted")
		}
		h, err := NormalizeHostname("adminHostname", s.AdminHostname)
		if err != nil {
			return err
		}
		s.AdminHostname = h
	}
	return nil
}

// CheckRoutes validates the whole route set, including rules that span
// routes (like the admin hostname not being used by a route).
func CheckRoutes(routes []store.Route, adminHostname string) error {
	for _, r := range routes {
		if adminHostname != "" && r.Hostname == adminHostname {
			return fieldErr("hostname", "%s is used for the RyProx admin dashboard", r.Hostname)
		}
	}
	return nil
}

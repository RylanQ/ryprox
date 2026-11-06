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
	"time"

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
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
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
	case u.RawPath != "" || strings.ContainsAny(u.Path, " \\") || strings.Contains(u.Path, "/../") || strings.HasSuffix(u.Path, "/.."):
		return "", fieldErr(field, "the path in this address isn't valid")
	}
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 1 || n > 65535 {
			return "", fieldErr(field, "port must be between 1 and 65535")
		}
	}
	u.Path = strings.TrimSuffix(u.Path, "/") // a base path like /app; requests are added after it
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
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum && strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
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
	switch c.Kind {
	case "", store.KindProxy:
		c.Kind = store.KindProxy
	case store.KindRedirect:
	default:
		return fieldErr("kind", "choose proxy or redirect")
	}
	if c.ExpiresAt != nil {
		t := c.ExpiresAt.UTC().Truncate(time.Second)
		c.ExpiresAt = &t
	}
	if c.RateLimit.RequestsPerMinute < 0 || c.RateLimit.RequestsPerMinute > 1_000_000 {
		return fieldErr("rateLimit.requestsPerMinute", "enter a number between 0 (no limit) and 1000000")
	}
	if c.IsRedirect() {
		err = normalizeRedirect(r)
	} else {
		err = normalizeProxy(c)
	}
	if err != nil {
		return err
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
	switch c.Access.Mode {
	case "", store.AccessPrivate:
		c.Access.Mode = store.AccessPrivate
	case store.AccessPublic:
	default:
		return fieldErr("access.mode", "choose private or public")
	}
	if len(c.Access.Users) > 10000 {
		return fieldErr("access.users", "too many people")
	}
	seenUsers := map[int64]bool{}
	users := c.Access.Users[:0]
	for _, id := range c.Access.Users {
		if id > 0 && !seenUsers[id] {
			seenUsers[id] = true
			users = append(users, id)
		}
	}
	c.Access.Users = users
	if c.Access.Users == nil {
		c.Access.Users = []int64{}
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

func normalizeProxy(c *store.RouteConfig) error {
	var err error
	c.Redirect = store.Redirect{}
	if c.Targets, err = normalizeTargets("targets", c.Targets); err != nil {
		return err
	}
	if c.LandingPath != "" {
		if !validPath(c.LandingPath) || c.LandingPath == "/" {
			return fieldErr("landingPath", "enter a path on this site, like /page1")
		}
	}
	if len(c.Paths) > MaxPathRules {
		return fieldErr("paths", "at most %d path rules", MaxPathRules)
	}
	prefixes := map[string]bool{}
	for i := range c.Paths {
		p := &c.Paths[i]
		f := fmt.Sprintf("paths.%d", i)
		p.Prefix = strings.TrimSpace(p.Prefix)
		if p.Prefix != "/" {
			p.Prefix = strings.TrimSuffix(p.Prefix, "/")
		}
		if !validPath(p.Prefix) || strings.ContainsAny(p.Prefix, "?") || p.Prefix == "/" {
			return fieldErr(f+".prefix", "enter a path like /api")
		}
		if strings.HasPrefix(p.Prefix+"/", "/.ryprox/") {
			return fieldErr(f+".prefix", "/.ryprox is reserved for RyProx")
		}
		if prefixes[p.Prefix] {
			return fieldErr(f+".prefix", "this path is listed twice")
		}
		prefixes[p.Prefix] = true
		if p.Targets, err = normalizeTargets(f+".targets", p.Targets); err != nil {
			return err
		}
	}
	if c.Paths == nil {
		c.Paths = []store.PathRule{}
	}
	return nil
}

// MaxPathRules is the most path rules a route may have.
const MaxPathRules = 50

func normalizeTargets(field string, ts []store.Target) ([]store.Target, error) {
	if len(ts) == 0 {
		return nil, fieldErr(field, "add at least one target")
	}
	if len(ts) > MaxTargets {
		return nil, fieldErr(field, "at most %d targets", MaxTargets)
	}
	seen := map[string]bool{}
	for i := range ts {
		f := fmt.Sprintf("%s.%d", field, i)
		u, err := NormalizeTargetURL(f, ts[i].URL)
		if err != nil {
			return nil, err
		}
		if seen[u] {
			return nil, fieldErr(f, "this target is listed twice")
		}
		seen[u] = true
		ts[i].URL = u
	}
	return ts, nil
}

// validPath accepts an absolute path on the same site: no scheme, no
// "//host", no backslashes or control characters, no dot segments.
func validPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || len(p) > 1024 {
		return false
	}
	if strings.ContainsAny(p, "\\ #\r\n\t\x00") {
		return false
	}
	path, _, _ := strings.Cut(p, "?")
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func normalizeRedirect(r *store.Route) error {
	c := &r.Config
	c.Targets, c.Paths, c.LandingPath = []store.Target{}, []store.PathRule{}, ""
	c.HealthCheck.Enabled = false
	rd := &c.Redirect
	rd.To = strings.TrimSpace(rd.To)
	u, err := url.Parse(rd.To)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || strings.ContainsAny(rd.To, " \r\n\x00\\") {
		return fieldErr("redirect.to", "enter the full address to send visitors to, like https://example.com")
	}
	if strings.EqualFold(u.Hostname(), r.Hostname) && (u.Path == "" || u.Path == "/") {
		return fieldErr("redirect.to", "this would send visitors back to the same address")
	}
	switch rd.Code {
	case 0:
		rd.Code = 301
	case 301, 302, 307, 308:
	default:
		return fieldErr("redirect.code", "choose permanent or temporary")
	}
	if rd.KeepPath {
		rd.To = strings.TrimSuffix(rd.To, "/")
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
	if s.AuthHostname != "" {
		if s.TLSMode != store.TLSModeACME {
			return fieldErr("authHostname", "a sign-in domain needs automatic HTTPS, so passwords are never sent unencrypted")
		}
		h, err := NormalizeHostname("authHostname", s.AuthHostname)
		if err != nil {
			return err
		}
		s.AuthHostname = h
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
// routes (like RyProx's own domains not being used by a route).
func CheckRoutes(routes []store.Route, s store.Settings) error {
	for _, r := range routes {
		if s.AdminHostname != "" && r.Hostname == s.AdminHostname {
			return fieldErr("hostname", "%s is used for the RyProx dashboard", r.Hostname)
		}
		if s.AuthHostname != "" && r.Hostname == s.AuthHostname {
			return fieldErr("hostname", "%s is used for RyProx's sign-in page", r.Hostname)
		}
	}
	return nil
}

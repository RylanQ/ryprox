// SPDX-License-Identifier: AGPL-3.0-only

package tunnel

import (
	"fmt"
	"net/netip"
	"strings"
)

// allowList limits where an agent will connect. Admins of the remote
// network can use it so a compromised RyProx can't reach everything there.
type allowList struct {
	prefixes []netip.Prefix
	hosts    map[string]bool
}

func parseAllow(items []string) (*allowList, error) {
	if len(items) == 0 {
		return nil, nil // anything
	}
	a := &allowList{hosts: map[string]bool{}}
	for _, it := range items {
		it = strings.TrimSpace(strings.ToLower(it))
		if it == "" {
			continue
		}
		if p, err := netip.ParsePrefix(it); err == nil {
			a.prefixes = append(a.prefixes, p.Masked())
			continue
		}
		if ip, err := netip.ParseAddr(it); err == nil {
			a.prefixes = append(a.prefixes, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		if strings.ContainsAny(it, "/ :") {
			return nil, fmt.Errorf("--allow %q isn't an address, range or host name", it)
		}
		a.hosts[it] = true
	}
	return a, nil
}

// permits checks a destination: its name is listed, or every address it
// resolves to is inside a listed range.
func (a *allowList) permits(host string, ips []netip.Addr) bool {
	if a == nil {
		return true
	}
	if a.hosts[strings.ToLower(strings.TrimSuffix(host, "."))] {
		return true
	}
	for _, ip := range ips {
		ok := false
		for _, p := range a.prefixes {
			if p.Contains(ip.Unmap()) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return len(ips) > 0
}

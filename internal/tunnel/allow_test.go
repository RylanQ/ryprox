// SPDX-License-Identifier: AGPL-3.0-only

package tunnel

import (
	"net/netip"
	"testing"
)

func TestAllowList(t *testing.T) {
	a, err := parseAllow([]string{"192.168.1.0/24", "10.0.0.5", "NAS.lan"})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr
	cases := []struct {
		host string
		ips  []netip.Addr
		want bool
	}{
		{"192.168.1.20", []netip.Addr{ip("192.168.1.20")}, true},
		{"10.0.0.5", []netip.Addr{ip("10.0.0.5")}, true},
		{"10.0.0.6", []netip.Addr{ip("10.0.0.6")}, false},
		{"nas.lan", []netip.Addr{ip("172.16.0.9")}, true},
		{"evil.example", []netip.Addr{ip("192.168.1.2"), ip("8.8.8.8")}, false}, // every address must be allowed
		{"x", nil, false},
	}
	for _, c := range cases {
		if got := a.permits(c.host, c.ips); got != c.want {
			t.Errorf("%s %v: %v", c.host, c.ips, got)
		}
	}
	var none *allowList
	if !none.permits("anything", []netip.Addr{ip("8.8.8.8")}) {
		t.Fatal("empty list should allow")
	}
	if _, err := parseAllow([]string{"http://x"}); err == nil {
		t.Fatal("bad entry accepted")
	}
}

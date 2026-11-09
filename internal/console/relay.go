// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// Remote desktops on a site go through that site's tunnel, but guacd makes
// the connection itself and knows nothing about tunnels. So RyProx opens a
// one-time relay: a listener that accepts a single connection, only from
// guacd, within a short time, and pipes it through the tunnel.

const relayWait = 30 * time.Second

// relayHost is how guacd reaches RyProx: 127.0.0.1 when both run on the
// same machine, or RyProx's container name with Docker (RYPROX_FORWARD_HOST).
func (s *Service) relayHost() string {
	if s.RelayHost != "" {
		return s.RelayHost
	}
	return "127.0.0.1"
}

// startRelay listens for guacd and returns the host and port to give it.
func (s *Service) startRelay(ctx context.Context, site int64, target, guacdAddr string) (string, string, error) {
	host := s.relayHost()
	bind := "0.0.0.0" // a container name: listen inside the container's private network
	if ip := net.ParseIP(host); ip != nil {
		bind = host
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(bind, "0"))
	if err != nil {
		return "", "", err
	}
	allowed := guacdIPs(ctx, guacdAddr)
	go func() {
		defer func() { _ = ln.Close() }()
		if tl, ok := ln.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(relayWait))
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			rip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if !allowed(net.ParseIP(rip)) {
				s.Log.Warn("refused a relay connection that didn't come from guacd", "from", rip)
				_ = c.Close()
				continue
			}
			_ = ln.Close() // one connection only
			s.pipeThroughTunnel(ctx, c, site, target)
			return
		}
	}()
	return host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), nil
}

func (s *Service) pipeThroughTunnel(ctx context.Context, c net.Conn, site int64, target string) {
	defer func() { _ = c.Close() }()
	if s.Dial == nil {
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	remote, err := s.Dial(dctx, site, target)
	cancel()
	if err != nil {
		s.Log.Warn("remote desktop through site failed", "target", target, "err", err)
		return
	}
	defer func() { _ = remote.Close() }()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, remote); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// guacdIPs returns a check for addresses guacd may connect from: the
// addresses its host name resolves to, plus loopback when it is local.
func guacdIPs(ctx context.Context, guacdAddr string) func(net.IP) bool {
	host, _, err := net.SplitHostPort(guacdAddr)
	if err != nil {
		host = guacdAddr
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil {
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	return func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		for _, x := range ips {
			if x.Equal(ip) || (x.IsLoopback() && ip.IsLoopback()) {
				return true
			}
		}
		return false
	}
}

var errNoRelay = errors.New("couldn't open the relay for this site")

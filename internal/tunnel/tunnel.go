// SPDX-License-Identifier: AGPL-3.0-only

// Package tunnel lets RyProx reach services on networks it can't connect
// to directly, such as a home behind CGNAT.
//
// A small agent ("ryprox connect") runs inside that network and opens an
// outbound WebSocket to RyProx over HTTPS. Many TCP streams are multiplexed
// over it with yamux. When RyProx needs a service at that site, it opens a
// stream and asks the agent to connect to the service's address.
//
// The remote network needs no open ports. Several agents can serve the same
// site; RyProx spreads new connections across those that are online, so one
// going down doesn't take the site with it.
package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// TokenPrefix starts every site token.
const TokenPrefix = "ryt_"

// Path is where agents connect, on the sign-in domain.
const Path = "/.ryprox/tunnel"

const (
	dialTimeout   = 10 * time.Second
	maxAddrLength = 300
)

// ErrOffline means no agent for the site is connected.
var ErrOffline = errors.New("the site's connector is offline")

func yamuxConfig(log *slog.Logger) *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 20 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	c.LogOutput = nil
	c.Logger = slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	return c
}

type agent struct {
	sess   *yamux.Session
	remote string
	since  time.Time
}

// Hub tracks connected agents on the RyProx server.
type Hub struct {
	log    *slog.Logger
	mu     sync.Mutex
	agents map[int64][]*agent
	next   atomic.Uint64
}

// NewHub returns an empty hub.
func NewHub(log *slog.Logger) *Hub {
	return &Hub{log: log, agents: map[int64][]*agent{}}
}

// AgentStatus describes one connected agent.
type AgentStatus struct {
	Remote string    `json:"remote"`
	Since  time.Time `json:"since"`
}

// Status lists connected agents per site.
func (h *Hub) Status() map[int64][]AgentStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[int64][]AgentStatus{}
	for id, as := range h.agents {
		for _, a := range as {
			if !a.sess.IsClosed() {
				out[id] = append(out[id], AgentStatus{Remote: a.remote, Since: a.since})
			}
		}
	}
	return out
}

// Online reports whether any agent serves the site.
func (h *Hub) Online(siteID int64) bool {
	return len(h.Status()[siteID]) > 0
}

// Disconnect closes every agent of a site (when the site is deleted or its
// token is replaced).
func (h *Hub) Disconnect(siteID int64) {
	h.mu.Lock()
	as := h.agents[siteID]
	delete(h.agents, siteID)
	h.mu.Unlock()
	for _, a := range as {
		_ = a.sess.Close()
	}
}

// Serve upgrades an authenticated agent request and keeps it until the
// agent goes away or ctx ends.
func (h *Hub) Serve(ctx context.Context, w http.ResponseWriter, r *http.Request, siteID int64) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"ryprox-tunnel"}})
	if err != nil {
		return
	}
	c.SetReadLimit(-1)
	conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	sess, err := yamux.Client(conn, yamuxConfig(h.log))
	if err != nil {
		_ = conn.Close()
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	a := &agent{sess: sess, remote: host, since: time.Now()}
	h.mu.Lock()
	h.agents[siteID] = append(h.agents[siteID], a)
	h.mu.Unlock()
	h.log.Info("tunnel connected", "site", siteID, "from", host)

	select {
	case <-sess.CloseChan():
	case <-ctx.Done():
		_ = sess.Close()
	}
	h.mu.Lock()
	list := h.agents[siteID]
	for i, x := range list {
		if x == a {
			h.agents[siteID] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(h.agents[siteID]) == 0 {
		delete(h.agents, siteID)
	}
	h.mu.Unlock()
	h.log.Info("tunnel disconnected", "site", siteID, "from", host)
}

// Dial connects to addr (host:port) inside a site, through one of its agents.
func (h *Hub) Dial(ctx context.Context, siteID int64, addr string) (net.Conn, error) {
	if len(addr) > maxAddrLength || strings.ContainsAny(addr, "\r\n") {
		return nil, errors.New("invalid address")
	}
	h.mu.Lock()
	var live []*agent
	for _, a := range h.agents[siteID] {
		if !a.sess.IsClosed() {
			live = append(live, a)
		}
	}
	h.mu.Unlock()
	if len(live) == 0 {
		return nil, ErrOffline
	}
	start := h.next.Add(1)
	var lastErr error
	for i := range live {
		a := live[(start+uint64(i))%uint64(len(live))]
		conn, err := dialVia(ctx, a.sess, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		var refused *RemoteError
		if errors.As(err, &refused) {
			return nil, err // the agent answered; another agent would say the same
		}
	}
	return nil, lastErr
}

// RemoteError is the agent's reason for not connecting.
type RemoteError struct{ Msg string }

func (e *RemoteError) Error() string { return "connector: " + e.Msg }

func dialVia(ctx context.Context, sess *yamux.Session, addr string) (net.Conn, error) {
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(dialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = st.SetDeadline(deadline)
	if _, err := io.WriteString(st, addr+"\n"); err != nil {
		_ = st.Close()
		return nil, err
	}
	br := bufio.NewReader(st)
	line, err := br.ReadString('\n')
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	_ = st.SetDeadline(time.Time{})
	line = strings.TrimSuffix(line, "\n")
	if line != "ok" {
		_ = st.Close()
		return nil, &RemoteError{Msg: strings.TrimPrefix(line, "err ")}
	}
	return &bufConn{Conn: st, r: br}, nil
}

// bufConn keeps bytes already buffered while reading the reply.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Agent is the "ryprox connect" side.
type Agent struct {
	Server string   // RyProx's sign-in address, e.g. https://login.example.com
	Token  string   // the site's token
	Allow  []string // CIDRs or host names the agent may connect to; empty means any
	// Address, if set, is the host:port to connect to instead of looking up
	// Server's name (to reach one particular server of several).
	Address string
	Log     *slog.Logger
	// HTTPClient is used for the WebSocket (tests use a client that trusts a test CA).
	HTTPClient *http.Client
}

// Run connects and serves until ctx ends, reconnecting with backoff.
func (a *Agent) Run(ctx context.Context) error {
	allow, err := parseAllow(a.Allow)
	if err != nil {
		return err
	}
	backoff := time.Second
	for {
		started := time.Now()
		err := a.once(ctx, allow)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		a.Log.Warn("tunnel disconnected; reconnecting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func (a *Agent) once(ctx context.Context, allow *allowList) error {
	u := strings.TrimSuffix(a.Server, "/") + Path
	u = "wss" + strings.TrimPrefix(strings.TrimPrefix(u, "https"), "http") // https:// → wss://
	if !strings.HasPrefix(a.Server, "https://") {
		return errors.New("the server address must start with https://")
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+a.Token)
	client := a.HTTPClient
	if client == nil && a.Address != "" {
		addr := a.Address
		client = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		}}}
	}
	c, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: h, HTTPClient: client, Subprotocols: []string{"ryprox-tunnel"}})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return errors.New("the token was refused; create a new one in the dashboard")
		}
		return err
	}
	c.SetReadLimit(-1)
	conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	sess, err := yamux.Server(conn, yamuxConfig(a.Log))
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = sess.Close() }()
	a.Log.Info("tunnel connected", "server", a.Server)
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go a.handle(ctx, st, allow)
	}
}

func (a *Agent) handle(ctx context.Context, st *yamux.Stream, allow *allowList) {
	defer func() { _ = st.Close() }()
	_ = st.SetDeadline(time.Now().Add(dialTimeout))
	br := bufio.NewReader(io.LimitReader(st, maxAddrLength+1))
	addr, err := br.ReadString('\n')
	if err != nil {
		return
	}
	addr = strings.TrimSuffix(addr, "\n")
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_, _ = io.WriteString(st, "err invalid address\n")
		return
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(dctx, "ip", host)
	if err != nil || len(ips) == 0 {
		_, _ = io.WriteString(st, "err can't find "+host+"\n")
		return
	}
	if !allow.permits(host, ips) {
		a.Log.Warn("tunnel refused a destination outside --allow", "addr", addr)
		_, _ = io.WriteString(st, "err "+host+" isn't allowed by this connector\n")
		return
	}
	_, port, _ := net.SplitHostPort(addr)
	target, err := (&net.Dialer{}).DialContext(dctx, "tcp", net.JoinHostPort(ips[0].String(), port))
	if err != nil {
		_, _ = io.WriteString(st, fmt.Sprintf("err couldn't connect to %s\n", addr))
		return
	}
	defer func() { _ = target.Close() }()
	if _, err := io.WriteString(st, "ok\n"); err != nil {
		return
	}
	_ = st.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, st); closeWrite(target); done <- struct{}{} }()
	go func() {
		_, _ = io.Copy(st, target)
		_ = st.Close() // yamux closes only our side; reading continues
		done <- struct{}{}
	}()
	select {
	case <-done:
		<-done
	case <-ctx.Done():
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/rylanq/ryprox/internal/store"
)

const (
	sshKeySetting      = "ssh_key"
	sshKeyPurpose      = "ssh-key"
	sshHostKeysSetting = "ssh_host_keys"
)

// signer returns RyProx's own SSH key, creating it on first use. Admins add
// its public half to ~/.ssh/authorized_keys on machines RyProx may open.
func (s *Service) signer(ctx context.Context) (ssh.Signer, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	sealed, err := s.Store.GetJSONSetting(ctx, sshKeySetting)
	if err != nil {
		return nil, err
	}
	if sealed == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(priv, "ryprox")
		if err != nil {
			return nil, err
		}
		if sealed, err = s.Box.Seal(string(pem.EncodeToMemory(block)), sshKeyPurpose); err != nil {
			return nil, err
		}
		if err := s.Store.SetJSONSetting(ctx, sshKeySetting, sealed); err != nil {
			return nil, err
		}
	}
	pemText, err := s.Box.Open(sealed, sshKeyPurpose)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey([]byte(pemText))
}

// PublicKey returns RyProx's SSH public key in authorized_keys format.
func (s *Service) PublicKey(ctx context.Context) (string, error) {
	sg, err := s.signer(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sg.PublicKey()))) + " ryprox", nil
}

// hostKeyCallback checks the server's key against the fingerprint set on
// the route, or the one learned the first time RyProx connected.
func (s *Service) hostKeyCallback(ctx context.Context, route *store.Route) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if want := route.Config.Console.HostKey; want != "" {
			if got != want {
				return fmt.Errorf("the server's key (%s) doesn't match the one set for this route", got)
			}
			return nil
		}
		s.keyMu.Lock()
		defer s.keyMu.Unlock()
		known := map[string]string{}
		if raw, err := s.Store.GetJSONSetting(ctx, sshHostKeysSetting); err == nil && raw != "" {
			_ = json.Unmarshal([]byte(raw), &known)
		}
		id := strconv.FormatInt(route.ID, 10) + "|" + route.Config.Console.Address
		if want, ok := known[id]; ok {
			if got != want {
				return fmt.Errorf("the server's key changed (now %s); if that's expected, an admin can reset it on the route", got)
			}
			return nil
		}
		known[id] = got // trust on first use
		b, _ := json.Marshal(known)
		return s.Store.SetJSONSetting(ctx, sshHostKeysSetting, string(b))
	}
}

// LearnedHostKey returns the fingerprint remembered for a route, if any.
func (s *Service) LearnedHostKey(ctx context.Context, route *store.Route) string {
	known := map[string]string{}
	if raw, err := s.Store.GetJSONSetting(ctx, sshHostKeysSetting); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &known)
	}
	return known[strconv.FormatInt(route.ID, 10)+"|"+route.Config.Console.Address]
}

// ForgetHostKey removes the remembered fingerprint for a route.
func (s *Service) ForgetHostKey(ctx context.Context, routeID int64) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	known := map[string]string{}
	if raw, err := s.Store.GetJSONSetting(ctx, sshHostKeysSetting); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &known)
	}
	prefix := strconv.FormatInt(routeID, 10) + "|"
	for k := range known {
		if strings.HasPrefix(k, prefix) {
			delete(known, k)
		}
	}
	b, _ := json.Marshal(known)
	return s.Store.SetJSONSetting(ctx, sshHostKeysSetting, string(b))
}

// Messages from the browser: "d" + keystrokes, or "r" + "cols,rows".
func (s *Service) runSSH(ctx context.Context, c *websocket.Conn, route *store.Route, t ticket) error {
	k := route.Config.Console
	cfg := &ssh.ClientConfig{
		User:            t.username,
		HostKeyCallback: s.hostKeyCallback(ctx, route),
		Timeout:         10 * time.Second,
	}
	if k.Auth == store.ConsoleAuthKey {
		sg, err := s.signer(ctx)
		if err != nil {
			closeWith(c, "RyProx's SSH key isn't available")
			return err
		}
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(sg)}
	} else {
		pw := t.password
		cfg.Auth = []ssh.AuthMethod{ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = pw
			}
			return ans, nil
		})}
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	raw, err := (&net.Dialer{}).DialContext(dctx, "tcp", k.Address)
	cancel()
	if err != nil {
		closeWith(c, "Couldn't reach "+k.Address)
		return err
	}
	sc, chans, reqs, err := ssh.NewClientConn(raw, k.Address, cfg)
	if err != nil {
		_ = raw.Close()
		msg := "Sign-in to the server failed"
		if strings.Contains(err.Error(), "key") && strings.Contains(err.Error(), "server's") {
			msg = err.Error()
		}
		closeWith(c, msg)
		return err
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer func() { _ = client.Close() }()
	sess, err := client.NewSession()
	if err != nil {
		closeWith(c, "The server refused a terminal")
		return err
	}
	defer func() { _ = sess.Close() }()
	cols, rows := 80, 24
	if err := sess.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}); err != nil {
		closeWith(c, "The server refused a terminal")
		return err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	out := &wsWriter{ctx: ctx, c: c}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		closeWith(c, "The server refused a shell")
		return err
	}

	ctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { // browser → server
		defer stop()
		for {
			_, msg, err := c.Read(ctx)
			if err != nil || len(msg) == 0 {
				return
			}
			switch msg[0] {
			case 'd':
				if _, err := stdin.Write(msg[1:]); err != nil {
					return
				}
			case 'r':
				var cc, rr int
				if _, err := fmt.Sscanf(string(msg[1:]), "%d,%d", &cc, &rr); err == nil && cc > 0 && rr > 0 && cc < 1000 && rr < 1000 {
					_ = sess.WindowChange(rr, cc)
				}
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case err = <-done:
		_ = c.Close(websocket.StatusNormalClosure, "Session ended")
		return err
	case <-ctx.Done():
		_ = c.Close(websocket.StatusNormalClosure, "Disconnected")
		return ctx.Err()
	}
}

type wsWriter struct {
	ctx context.Context
	c   *websocket.Conn
}

func (w *wsWriter) Write(p []byte) (int, error) {
	if err := w.c.Write(w.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

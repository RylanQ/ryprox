// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/rylanq/ryprox/internal/console"
	"github.com/rylanq/ryprox/internal/web"
)

// sshServer runs a tiny SSH server whose shell echoes input in upper case.
func sshServer(t *testing.T, user, password string) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == user && string(pw) == password {
			return nil, nil
		}
		return nil, io.EOF
	}}
	cfg.AddHostKey(hostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, _ := nch.Accept()
					go func() {
						for req := range creqs {
							_ = req.Reply(req.Type == "pty-req" || req.Type == "shell" || req.Type == "window-change", nil)
							if req.Type == "shell" {
								_, _ = io.WriteString(ch, "welcome\r\n")
								go func() {
									buf := make([]byte, 1024)
									for {
										n, err := ch.Read(buf)
										if err != nil {
											return
										}
										_, _ = ch.Write(bytes.ToUpper(buf[:n]))
									}
								}()
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// consoleEnv serves the proxy engine over TLS, with the console service.
func consoleEnv(t *testing.T) (*env, *client, *httptest.Server, string) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	ui := web.Static()
	e.srv.Console = &console.Service{Store: e.srv.Store, Box: e.srv.Box, Log: slog.New(slog.DiscardHandler), UI: ui,
		Audit: e.srv.Audit}
	e.engine.SetConsole(e.srv.Console)
	ts := httptest.NewTLSServer(e.engine)
	t.Cleanup(ts.Close)
	_, out := admin.post("/api/account/tokens", map[string]any{"name": "t", "scope": "sites"})
	return e, admin, ts, out["token"].(string)
}

func consoleClient(ts *httptest.Server) *http.Client {
	addr := ts.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}}
}

func consoleTicket(t *testing.T, ts *httptest.Server, host, token string, body map[string]any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(t.Context(), "POST", "https://"+host+"/session", bytes.NewReader(b))
	req.Header.Set("X-RyProx-Token", token)
	req.Header.Set("X-RyProx", "1")
	resp, err := consoleClient(ts).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out["ticket"]
}

func dialConsole(t *testing.T, ts *httptest.Server, host, token, ticket string, proto []string) (*websocket.Conn, error) {
	h := http.Header{}
	h.Set("X-RyProx-Token", token)
	c, _, err := websocket.Dial(t.Context(), "wss://"+host+"/ws?ticket="+ticket,
		&websocket.DialOptions{HTTPClient: consoleClient(ts), HTTPHeader: h, Subprotocols: proto})
	return c, err
}

func TestSSHConsole(t *testing.T) {
	e, admin, ts, token := consoleEnv(t)
	addr := sshServer(t, "sam", "hunter22")
	code, out := admin.post("/api/routes", map[string]any{"hostname": "ssh.example.com", "enabled": true,
		"config": map[string]any{"kind": "ssh", "access": map[string]any{"mode": "private", "users": []int64{1}},
			"console": map[string]any{"address": addr, "auth": "ask"}}})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	// Consoles can't be public.
	if code, _ := admin.post("/api/routes", map[string]any{"hostname": "ssh2.example.com",
		"config": map[string]any{"kind": "ssh", "access": map[string]any{"mode": "public"}, "console": map[string]any{"address": addr}}}); code != 400 {
		t.Fatalf("public console: %d", code)
	}

	status, tk := consoleTicket(t, ts, "ssh.example.com", token, map[string]any{"username": "sam", "password": "hunter22"})
	if status != 200 || tk == "" {
		t.Fatalf("ticket: %d", status)
	}
	c, err := dialConsole(t, ts, "ssh.example.com", token, tk, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	read := func(want string) {
		var got strings.Builder
		for !strings.Contains(got.String(), want) {
			_, b, err := c.Read(ctx)
			if err != nil {
				t.Fatalf("waiting for %q, got %q: %v", want, got.String(), err)
			}
			got.Write(b)
		}
	}
	read("welcome")
	_ = c.Write(ctx, websocket.MessageText, []byte("r100,30"))
	_ = c.Write(ctx, websocket.MessageText, []byte("dhello"))
	read("HELLO")

	// A ticket works once, and only for the person it was made for.
	if _, err := dialConsole(t, ts, "ssh.example.com", token, tk, nil); err == nil {
		t.Fatal("ticket reused")
	}
	// The host key was learned on first use.
	_, hk := admin.req("GET", "/api/routes/1/host-key", nil, nil)
	if !strings.HasPrefix(hk["learned"].(string), "SHA256:") {
		t.Fatalf("host key not learned: %v", hk)
	}
	// Wrong password: the socket closes with a reason.
	_, tk2 := consoleTicket(t, ts, "ssh.example.com", token, map[string]any{"username": "sam", "password": "nope"})
	c2, err := dialConsole(t, ts, "ssh.example.com", token, tk2, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c2.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("wrong password: %v", err)
	}
	// Without access, nothing.
	if s, _ := consoleTicket(t, ts, "ssh.example.com", "ryp_bad", map[string]any{}); s != 401 {
		t.Fatalf("no access: %d", s)
	}
	_ = e
}

func TestGuacRelay(t *testing.T) {
	_, admin, ts, token := consoleEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan string, 10)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		readUntil := func(opcode string) string {
			for {
				line, err := br.ReadString(';')
				if err != nil {
					return ""
				}
				if strings.Contains(line, "."+opcode+",") || strings.Contains(line, "."+opcode+";") {
					return line
				}
			}
		}
		readUntil("select")
		_, _ = io.WriteString(conn, "4.args,13.VERSION_1_5_0,8.hostname,4.port,8.username,8.password,6.domain;")
		got <- readUntil("connect")
		_, _ = io.WriteString(conn, "5.ready,4.$abc;4.sync,1.1;")
		got <- readUntil("mouse")
	}()
	code, out := admin.post("/api/routes", map[string]any{"hostname": "pc.example.com", "enabled": true,
		"config": map[string]any{"kind": "rdp", "access": map[string]any{"mode": "private", "users": []int64{1}},
			"console": map[string]any{"address": "10.9.8.7", "username": "Rylan", "auth": "stored", "password": "s3cr3t", "domain": "HOME"}}})
	if code != 201 || out["config"].(map[string]any)["console"].(map[string]any)["password"] != nil {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, _ := admin.req("PUT", "/api/console", map[string]string{"guacd": ln.Addr().String()}, nil); code != 200 {
		t.Fatal("set guacd")
	}
	_, tk := consoleTicket(t, ts, "pc.example.com", token, map[string]any{"width": 1024, "height": 768})
	c, err := dialConsole(t, ts, "pc.example.com", token, tk, []string{"guacamole"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	connect := <-got
	if connect != "7.connect,13.VERSION_1_5_0,8.10.9.8.7,4.3389,5.Rylan,6.s3cr3t,4.HOME;" {
		t.Fatalf("connect: %q", connect)
	}
	_, first, _ := c.Read(ctx)
	if string(first) != "0.,4.$abc;" {
		t.Fatalf("tunnel id: %q", first)
	}
	_, second, _ := c.Read(ctx)
	if string(second) != "4.sync,1.1;" {
		t.Fatalf("sync: %q", second)
	}
	// Pings are answered by RyProx; other instructions reach guacd.
	_ = c.Write(ctx, websocket.MessageText, []byte("0.,4.ping,3.123;5.mouse,1.1,1.2;"))
	_, pong, _ := c.Read(ctx)
	if string(pong) != "0.,4.ping,3.123;" {
		t.Fatalf("pong: %q", pong)
	}
	if m := <-got; m != "5.mouse,1.1,1.2;" {
		t.Fatalf("mouse: %q", m)
	}
}

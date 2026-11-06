// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"

	"github.com/rylanq/ryprox/internal/store"
)

// The Guacamole protocol: instructions are comma-separated elements ending
// in ";", each written as LENGTH.VALUE where LENGTH counts Unicode
// characters. The first element is the opcode.

const (
	guacdSetting  = "guacd"
	defaultGuacd  = "127.0.0.1:4822"
	maxInstrBytes = 8 << 20
)

// GuacdConfig is where guacd listens.
type GuacdConfig struct {
	Address string `json:"address"`
}

// Guacd returns the configured guacd address.
func (s *Service) Guacd(ctx context.Context) string {
	raw, err := s.Store.GetJSONSetting(ctx, guacdSetting)
	if err != nil || raw == "" {
		return defaultGuacd
	}
	var c GuacdConfig
	if json.Unmarshal([]byte(raw), &c) != nil || c.Address == "" {
		return defaultGuacd
	}
	return c.Address
}

// SetGuacd saves the guacd address.
func (s *Service) SetGuacd(ctx context.Context, addr string) error {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return errors.New("enter guacd's address as host:port, like 127.0.0.1:4822")
	}
	b, _ := json.Marshal(GuacdConfig{Address: addr})
	return s.Store.SetJSONSetting(ctx, guacdSetting, string(b))
}

// CheckGuacd reports whether guacd answers at addr.
func CheckGuacd(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, encode("select", "vnc")); err != nil {
		return err
	}
	ins, err := readInstruction(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	if len(ins) == 0 || ins[0] != "args" {
		return errors.New("that doesn't look like guacd")
	}
	return nil
}

func encode(elems ...string) string {
	var b strings.Builder
	for i, e := range elems {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(utf8.RuneCountInString(e)))
		b.WriteByte('.')
		b.WriteString(e)
	}
	b.WriteByte(';')
	return b.String()
}

// readInstruction reads one instruction and returns its elements.
func readInstruction(r *bufio.Reader) ([]string, error) {
	_, elems, err := readRaw(r)
	return elems, err
}

// readRaw reads one instruction, returning its exact text and elements.
func readRaw(r *bufio.Reader) (string, []string, error) {
	var raw strings.Builder
	var elems []string
	for {
		lenStr, err := r.ReadString('.')
		if err != nil {
			return "", nil, err
		}
		n, err := strconv.Atoi(lenStr[:len(lenStr)-1])
		if err != nil || n < 0 || n > maxInstrBytes {
			return "", nil, errors.New("malformed instruction")
		}
		raw.WriteString(lenStr)
		var val strings.Builder
		for i := 0; i < n; i++ {
			ch, _, err := r.ReadRune()
			if err != nil {
				return "", nil, err
			}
			val.WriteRune(ch)
		}
		if val.Len() > maxInstrBytes || raw.Len() > maxInstrBytes {
			return "", nil, errors.New("instruction too long")
		}
		raw.WriteString(val.String())
		elems = append(elems, val.String())
		sep, err := r.ReadByte()
		if err != nil {
			return "", nil, err
		}
		raw.WriteByte(sep)
		switch sep {
		case ';':
			return raw.String(), elems, nil
		case ',':
		default:
			return "", nil, errors.New("malformed instruction")
		}
	}
}

// guacParams maps guacd's argument names to values for this route.
func (s *Service) guacParams(route *store.Route, t ticket, password string) map[string]string {
	k := route.Config.Console
	host, port, _ := net.SplitHostPort(k.Address)
	p := map[string]string{
		"hostname": host,
		"port":     port,
		"password": password,
	}
	switch route.Config.Kind {
	case store.KindRDP:
		p["username"] = t.username
		p["domain"] = k.Domain
		p["security"] = k.Security
		if k.IgnoreCert {
			p["ignore-cert"] = "true"
		}
		p["resize-method"] = "display-update"
		p["width"], p["height"], p["dpi"] = strconv.Itoa(t.width), strconv.Itoa(t.height), strconv.Itoa(t.dpi)
		p["disable-audio"] = "true"
		p["enable-drive"] = "false"
		p["enable-printing"] = "false"
	case store.KindVNC:
		if t.username != "" {
			p["username"] = t.username // macOS Screen Sharing uses an account name
		}
		p["color-depth"] = "24"
	}
	return p
}

func (s *Service) runGuac(ctx context.Context, c *websocket.Conn, route *store.Route, t ticket) error {
	password, err := s.password(route, t)
	if err != nil {
		closeWith(c, "The saved password couldn't be unlocked")
		return err
	}
	addr := s.Guacd(ctx)
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	cancel()
	if err != nil {
		closeWith(c, "Remote desktop service (guacd) isn't running")
		return fmt.Errorf("guacd: %w", err)
	}
	defer func() { _ = conn.Close() }()
	br := bufio.NewReaderSize(conn, 64<<10)

	// Handshake: select the protocol, answer the arguments guacd asks for.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, encode("select", route.Config.Kind)); err != nil {
		return err
	}
	args, err := readInstruction(br)
	if err != nil || len(args) == 0 || args[0] != "args" {
		closeWith(c, "Remote desktop service didn't answer")
		return fmt.Errorf("guacd handshake: %v %v", args, err)
	}
	params := s.guacParams(route, t, password)
	values := []string{"connect"}
	for i, name := range args[1:] {
		if i == 0 && strings.HasPrefix(name, "VERSION_") {
			values = append(values, name)
			continue
		}
		values = append(values, params[name])
	}
	hs := encode("size", strconv.Itoa(t.width), strconv.Itoa(t.height), strconv.Itoa(t.dpi)) +
		encode("audio") + encode("video") +
		encode("image", "image/png", "image/jpeg", "image/webp") +
		encode("timezone", time.Local.String()) +
		encode(values...)
	if _, err := io.WriteString(conn, hs); err != nil {
		return err
	}
	ready, err := readInstruction(br)
	if err != nil || len(ready) < 2 || ready[0] != "ready" {
		closeWith(c, "Couldn't start the remote desktop")
		return fmt.Errorf("guacd ready: %v %v", ready, err)
	}
	_ = conn.SetDeadline(time.Time{})

	ctx, stop := context.WithCancel(ctx)
	defer stop()
	// The browser's tunnel expects its ID first.
	if err := c.Write(ctx, websocket.MessageText, []byte(encode("", ready[1]))); err != nil {
		return err
	}

	go func() { // browser → guacd
		defer stop()
		for {
			_, msg, err := c.Read(ctx)
			if err != nil {
				return
			}
			mr := bufio.NewReader(strings.NewReader(string(msg)))
			for {
				raw, elems, err := readRaw(mr)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return
				}
				if elems[0] == "" { // tunnel-internal: answer pings ourselves
					if len(elems) >= 2 && elems[1] == "ping" {
						_ = c.Write(ctx, websocket.MessageText, []byte(raw))
					}
					continue
				}
				if _, err := io.WriteString(conn, raw); err != nil {
					return
				}
			}
		}
	}()
	go func() { <-ctx.Done(); _ = conn.Close() }()

	// guacd → browser, batching whole instructions into each message.
	var batch strings.Builder
	for {
		raw, elems, err := readRaw(br)
		if err != nil {
			if ctx.Err() != nil {
				_ = c.Close(websocket.StatusNormalClosure, "Disconnected")
				return ctx.Err()
			}
			_ = c.Close(websocket.StatusNormalClosure, "Session ended")
			return nil
		}
		batch.WriteString(raw)
		if elems[0] == "sync" || br.Buffered() == 0 || batch.Len() > 32<<10 {
			if err := c.Write(ctx, websocket.MessageText, []byte(batch.String())); err != nil {
				return err
			}
			batch.Reset()
		}
	}
}

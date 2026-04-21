// Package pty implements the per-site PTY bridge used by the v2 browser
// terminal. The warden spawns a login shell as the site's Linux user via
// sudo and pipes stdio over a WebSocket.
//
// Wire protocol
//
// Client → server is plain UTF-8 binary frames carrying raw keystrokes.
// A frame whose first two bytes are the ASCII prefix "~s" carries a JSON
// resize directive {"cols":N,"rows":N} — it is consumed by this package
// and not written to the PTY.
//
// Server → client is whatever the PTY emits, streamed as binary frames.
//
// A session has two hard bounds: idle timeout (no client traffic for
// IdleTimeout kills it) and MaxDuration from spawn. Both are enforced
// by the supervisor goroutine.
//
// Auth is handled at the HTTP layer in handler.go — this file is pure
// PTY/WebSocket plumbing.
package pty

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	// IdleTimeout kills sessions after this long with no client input.
	IdleTimeout = 15 * time.Minute
	// MaxDuration kills sessions this long after spawn regardless of activity.
	MaxDuration = 2 * time.Hour
	// resizePrefix marks an inbound resize directive frame.
	resizePrefix = "~s"
	// readBufSize is the per-read buffer for PTY → WS forwarding.
	readBufSize = 4 * 1024
)

// resizeMsg is the payload after resizePrefix.
type resizeMsg struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// Session owns a live PTY + WS pair.
type Session struct {
	username     string
	ws           *websocket.Conn
	cmd          *exec.Cmd
	pty          *os.File
	lastActivity time.Time
	startedAt    time.Time
	mu           sync.Mutex
	closed       bool
}

// Start spawns a bash login shell as the given site user, wires the PTY
// to the WebSocket, and blocks until the session exits.
//
// The username must already be a validated "site_<short>" system user;
// this package does NO auth — callers (handler.go) are responsible.
func Start(ws *websocket.Conn, username string) error {
	if !validSiteUsername(username) {
		return fmt.Errorf("pty: invalid username %q", username)
	}

	// sudo -u site_xxx -i /bin/bash runs a login shell in the site's $HOME.
	// -i gives the user their normal environment and cwd. sudoers on the host
	// is pre-configured to permit warden → site_* without a password.
	cmd := exec.Command("sudo", "-u", username, "-i", "/bin/bash")
	cmd.Env = []string{
		"TERM=xterm-256color",
		"LANG=C.UTF-8",
	}

	p, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		return fmt.Errorf("pty: start bash: %w", err)
	}

	s := &Session{
		username:     username,
		ws:           ws,
		cmd:          cmd,
		pty:          p,
		lastActivity: time.Now(),
		startedAt:    time.Now(),
	}
	log.Printf("[pty] session START user=%s pid=%d", username, cmd.Process.Pid)

	errCh := make(chan error, 3)
	go func() { errCh <- s.pumpPTYToWS() }()
	go func() { errCh <- s.pumpWSToPTY() }()
	go func() { errCh <- s.superviseTimeouts() }()

	firstErr := <-errCh
	s.Close()
	log.Printf("[pty] session END user=%s pid=%d dur=%s reason=%v",
		username, cmd.Process.Pid, time.Since(s.startedAt).Round(time.Second), firstErr)
	return firstErr
}

// Close tears down both sides. Safe to call multiple times.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	_ = s.ws.Close()
	if s.pty != nil {
		_ = s.pty.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

func (s *Session) touch() {
	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()
}

// pumpPTYToWS forwards stdout/stderr from the PTY to the WebSocket.
func (s *Session) pumpPTYToWS() error {
	buf := make([]byte, readBufSize)
	for {
		n, err := s.pty.Read(buf)
		if n > 0 {
			_ = s.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if wErr := s.ws.WriteMessage(websocket.BinaryMessage, buf[:n]); wErr != nil {
				return fmt.Errorf("ws write: %w", wErr)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("pty read: %w", err)
		}
	}
}

// pumpWSToPTY forwards client keystrokes (and resize directives) into the PTY.
func (s *Session) pumpWSToPTY() error {
	for {
		_ = s.ws.SetReadDeadline(time.Now().Add(IdleTimeout + time.Minute))
		_, data, err := s.ws.ReadMessage()
		if err != nil {
			return fmt.Errorf("ws read: %w", err)
		}
		s.touch()

		if len(data) > len(resizePrefix) && string(data[:len(resizePrefix)]) == resizePrefix {
			s.handleResize(data[len(resizePrefix):])
			continue
		}

		if _, err := s.pty.Write(data); err != nil {
			return fmt.Errorf("pty write: %w", err)
		}
	}
}

// handleResize parses and applies a window-size directive. Malformed frames are dropped.
func (s *Session) handleResize(payload []byte) {
	payload = []byte(strings.TrimSpace(string(payload)))
	var m resizeMsg
	if err := json.Unmarshal(payload, &m); err != nil {
		return
	}
	if m.Cols == 0 || m.Rows == 0 {
		return
	}
	_ = pty.Setsize(s.pty, &pty.Winsize{Cols: m.Cols, Rows: m.Rows})
}

// superviseTimeouts kills the session when either limit trips.
func (s *Session) superviseTimeouts() error {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		idle := time.Since(s.lastActivity)
		live := time.Since(s.startedAt)
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return nil
		}
		if idle > IdleTimeout {
			return fmt.Errorf("pty: idle timeout (%s)", idle.Round(time.Second))
		}
		if live > MaxDuration {
			return fmt.Errorf("pty: max session duration reached (%s)", live.Round(time.Second))
		}
	}
	return nil
}

// validSiteUsername mirrors the filemgr rule: must start with "site_" and
// contain only the charset that provisioning.SiteUsername can emit.
func validSiteUsername(u string) bool {
	if !strings.HasPrefix(u, "site_") || len(u) > 32 {
		return false
	}
	for _, r := range u[5:] {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

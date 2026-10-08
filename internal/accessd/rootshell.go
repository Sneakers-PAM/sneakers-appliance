// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootshell"
)

// DefaultElevated is sneakers-elevated on the box.
const DefaultElevated = "/usr/libexec/sneakers-elevated"

// handshakeWait bounds how long a connection may take to send its
// handshake.
const handshakeWait = 10 * time.Second

// ServeRootShells takes closed shells' root-shell connections on ln (a
// PeerListener that lets admin uids only through) until ctx ends. Each
// connection's handshake carries a ticket; sneakers-elevated runs the root
// shell with the connection as its terminal, and the ticket is checked
// against the admin of the connection's uid, never one the client names.
func (s *Server) ServeRootShells(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.o.Logger.Error(err, "accessd: the root-shell socket stopped")
			}
			return
		}
		p, ok := initapi.PeerFrom(initapi.PeerContext(ctx, c))
		if !ok {
			_ = c.Close()
			continue
		}
		go s.RootShellConn(ctx, initapi.Underlying(c), p.UID)
	}
}

// RootShellConn serves one root-shell connection from uid: the admin of
// that uid, never one the client names. It closes c.
func (s *Server) RootShellConn(ctx context.Context, c net.Conn, uid uint32) {
	defer func() { _ = c.Close() }()
	st := s.store.Read()
	a, ok := st.AdminByUID(int(uid))
	if !ok {
		s.o.Logger.Warn("accessd: a root-shell connection from a uid with no admin; refused", log.F("uid", uid))
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(handshakeWait))
	h, rest, err := rootshell.ReadHandshake(c)
	if err != nil {
		s.o.Logger.Warn("accessd: a root-shell handshake didn't read", log.F("admin", a.Name), log.F("error", err.Error()))
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return
	}
	f, err := uc.File()
	if err != nil {
		s.o.Logger.Error(err, "accessd: the root-shell connection can't be handed on", log.F("admin", a.Name))
		return
	}
	defer func() { _ = f.Close() }()
	bin := s.o.Elevated
	if bin == "" {
		bin = DefaultElevated
	}
	// The handshake reader may hold bytes the client sent right after the
	// handshake; they go to sneakers-elevated through a pipe ahead of the
	// connection.
	pr, pw, err := os.Pipe()
	if err != nil {
		return
	}
	cmd := exec.Command(bin) // #nosec G204 -- the fixed sneakers-elevated
	cmd.Env = []string{
		"SNEAKERS_ROOT_TICKET=" + h.Ticket, "SNEAKERS_ROOT_ADMIN=" + a.Name,
		"SNEAKERS_ROOT_ROWS=" + strconv.Itoa(int(h.Rows)), "SNEAKERS_ROOT_COLS=" + strconv.Itoa(int(h.Cols)),
		"TERM=" + h.Term, "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pr, f, f
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		s.o.Logger.Error(err, "accessd: sneakers-elevated didn't start", log.F("admin", a.Name))
		_, _ = fmt.Fprintf(c, "\r\nThe root shell didn't start.\r\n")
		return
	}
	_ = pr.Close()
	s.o.Logger.Info("accessd: a root shell is starting", log.F("admin", a.Name), log.F("pid", cmd.Process.Pid))
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := rest.Read(buf)
			if n > 0 {
				if _, werr := pw.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = pw.Close()
	}()
	if err := cmd.Wait(); err != nil {
		s.o.Logger.Warn("accessd: a root shell ended with an error", log.F("admin", a.Name), log.F("error", err.Error()))
	}
}

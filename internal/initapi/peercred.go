// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// RootOnly allows uid 0.
func RootOnly(uid uint32) bool { return uid == 0 }

// Peer is the credentials of the process on the other end of a connection.
type Peer struct {
	UID, GID uint32
	PID      int32
}

type peerKey struct{}

// PeerFrom returns the connection's peer, set for every request.
func PeerFrom(ctx context.Context) (Peer, bool) {
	p, ok := ctx.Value(peerKey{}).(Peer)
	return p, ok
}

// peerListener reads every accepted connection's peer with SO_PEERCRED and
// closes it before a byte is read unless allow accepts the uid.
type peerListener struct {
	net.Listener
	allow func(uint32) bool
	logf  func(format string, args ...any)
}

type peerConn struct {
	net.Conn
	peer Peer
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		p, err := peerOf(c)
		if err != nil || !l.allow(p.UID) {
			l.logf("initapi: refused a connection from uid %d (%v)", p.UID, err)
			_ = c.Close()
			continue
		}
		return peerConn{Conn: c, peer: p}, nil
	}
}

func peerOf(c net.Conn) (Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) // #nosec G115 -- a socket descriptor fits an int
	}); err != nil {
		return Peer{}, err
	}
	if serr != nil {
		return Peer{}, serr
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

// PeerListener wraps ln so every accepted connection's peer is read with
// SO_PEERCRED, and the connection closed before a byte is read unless allow
// accepts its uid. Other daemons' sockets use it too.
func PeerListener(ln net.Listener, allow func(uint32) bool, logf func(format string, args ...any)) net.Listener {
	return peerListener{Listener: ln, allow: allow, logf: logf}
}

// PeerContext puts c's peer on ctx, for an http.Server's ConnContext.
func PeerContext(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(peerConn); ok {
		return context.WithValue(ctx, peerKey{}, pc.peer)
	}
	return ctx
}

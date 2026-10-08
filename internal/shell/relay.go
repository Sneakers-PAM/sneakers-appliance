// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootshell"
)

// pollEvery is how often the relay looks up from the terminal to see
// whether the root shell has ended, so no key is lost to it afterwards.
const pollEvery = 100 * time.Millisecond

// Relay opens the root shell on socket with ticket and copies the
// terminal: in's keys go to it in frames, its output to out, and each size
// from resize follows (size gives the first). It returns when the root
// shell ends or ctx does. in is read only when it has input, so the next
// key after the end stays for the menu.
func Relay(ctx context.Context, socket, ticket, term string, in *os.File, out io.Writer, size func() (rows, cols uint16), resize <-chan struct{}) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("the root shell can't be opened: %w", err)
	}
	defer func() { _ = conn.Close() }()
	rows, cols := size()
	if err := rootshell.WriteHandshake(conn, rootshell.Handshake{Ticket: ticket, Term: term, Rows: rows, Cols: cols}); err != nil {
		return fmt.Errorf("the root shell can't be opened: %w", err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(out, conn)
		close(done)
	}()
	fd := int(in.Fd()) // #nosec G115 -- a file descriptor fits an int
	buf := make([]byte, 4096)
	for {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return nil
		case <-resize:
			r, c := size()
			if err := rootshell.WriteResize(conn, r, c); err != nil {
				return nil
			}
			continue
		default:
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}} // #nosec G115 -- a file descriptor
		n, err := unix.Poll(fds, int(pollEvery.Milliseconds()))
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if n == 0 || fds[0].Revents == 0 {
			continue
		}
		select {
		case <-resize:
			// A resize that came in while polling goes before the keys.
			r, c := size()
			if err := rootshell.WriteResize(conn, r, c); err != nil {
				return nil
			}
		default:
		}
		k, err := in.Read(buf)
		if k > 0 {
			if werr := rootshell.WriteData(conn, buf[:k]); werr != nil {
				<-done
				return nil
			}
		}
		if err != nil {
			_ = conn.(*net.UnixConn).CloseWrite()
			<-done
			return nil
		}
	}
}

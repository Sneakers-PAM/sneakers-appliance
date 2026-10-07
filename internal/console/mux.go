// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package console makes PID 1's console every console the kernel has
// enabled, not just the one /dev/console names. The kernel points
// /dev/console at the last console= on its command line (ttyS0 on the
// appliance), so without this a VM with a screen but no serial port shows
// nothing from init and can't answer the Secure Boot choice. Output is
// copied to every console; a line typed on any of them reaches init.
package console

import (
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// ActivePath lists the consoles the kernel writes its own messages to.
const ActivePath = "/sys/class/tty/console/active"

// queueLen is how many output chunks a slow console may fall behind by
// before it starts losing output, so one stuck line can't stop the rest.
const queueLen = 256

// Names reads the active list ("tty0 ttyS0").
func Names(active string) []string { return strings.Fields(active) }

// Console is one terminal init talks on.
type Console struct {
	Name string
	RW   io.ReadWriter
}

// Mux copies init's output to every console and every console's input to
// init. A program can own the consoles for a while (Attach): its output
// then goes to every console and everyone else's goes aside.
type Mux struct {
	pending atomic.Int64
	queues  []chan []byte
	owners  atomic.Int32

	mu    sync.Mutex
	aside io.Writer
}

// Join copies out to every console and what's typed on each console to in,
// until out ends. A console whose write fails gets nothing more; logf
// reports it.
func Join(out io.Reader, in io.Writer, cons []Console, logf func(string, ...any)) *Mux {
	m := &Mux{}
	for _, c := range cons {
		q := make(chan []byte, queueLen)
		m.queues = append(m.queues, q)
		go m.write(c, q, logf)
		go typed(c, in)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := out.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				if m.Owned() {
					m.toAside(chunk)
				} else {
					m.send(chunk)
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return m
}

// send queues chunk for every console; a console that has fallen too far
// behind loses it.
func (m *Mux) send(chunk []byte) {
	for _, q := range m.queues {
		m.pending.Add(1)
		select {
		case q <- chunk:
		default:
			m.pending.Add(-1)
		}
	}
}

// SetAside sets where the shared output goes while a program owns the
// consoles; nil drops it.
func (m *Mux) SetAside(w io.Writer) {
	m.mu.Lock()
	m.aside = w
	m.mu.Unlock()
}

func (m *Mux) toAside(chunk []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.aside != nil {
		_, _ = m.aside.Write(chunk)
	}
}

// Attach gives the consoles to the program writing owner, until owner
// ends. The shared output goes aside meanwhile; afterwards the consoles
// get a fresh line with the colours reset, then the shared output again.
func (m *Mux) Attach(owner io.Reader) {
	m.owners.Add(1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := owner.Read(buf)
			if n > 0 {
				m.send(append([]byte(nil), buf[:n]...))
			}
			if err != nil {
				m.send([]byte("\x1b[0m\r\n"))
				m.owners.Add(-1)
				if c, ok := owner.(io.Closer); ok {
					_ = c.Close()
				}
				return
			}
		}
	}()
}

// Owned reports whether a program owns the consoles.
func (m *Mux) Owned() bool { return m.owners.Load() > 0 }

func (m *Mux) write(c Console, q <-chan []byte, logf func(string, ...any)) {
	broken := false
	for chunk := range q {
		if !broken {
			if _, err := c.RW.Write(chunk); err != nil {
				broken = true
				logf("console: %s stopped taking output: %v", c.Name, err)
			}
		}
		m.pending.Add(-1)
	}
}

func typed(c Console, in io.Writer) {
	buf := make([]byte, 1024)
	for {
		n, err := c.RW.Read(buf)
		if n > 0 {
			if _, werr := in.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Idle reports whether every chunk read so far has been written (or
// dropped) on every console.
func (m *Mux) Idle() bool { return m.pending.Load() == 0 }

// LogFile is where the shared output goes while a program owns the
// consoles: appended to Path, which rolls over to Path.1 past Max bytes.
type LogFile struct {
	Path string
	Max  int64

	mu   sync.Mutex
	f    *os.File
	size int64
}

func (l *LogFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil && l.size+int64(len(p)) > l.Max {
		_ = l.f.Close()
		l.f = nil
		_ = os.Rename(l.Path, l.Path+".1")
	}
	if l.f == nil {
		f, err := os.OpenFile(l.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return 0, err
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return 0, err
		}
		l.f, l.size = f, st.Size()
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

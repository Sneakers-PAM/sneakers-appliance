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
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ActivePath lists the consoles the kernel writes its own messages to.
const ActivePath = "/sys/class/tty/console/active"

// EarlyMax bounds the shared output kept before a recorder is set (the boot
// before the state volume opens); past it the rest of that output isn't
// kept for the recorder.
const EarlyMax = 256 << 10

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
// then goes to every console and everyone else's goes aside. Quiet keeps
// the shared output off the screens (it goes to the serial lines and
// aside), and Hold keeps everything off them but one page.
type Mux struct {
	pending atomic.Int64
	queues  []chan []byte
	screens []bool
	owners  atomic.Int32
	quiet   atomic.Bool
	held    atomic.Bool

	mu    sync.Mutex
	aside io.Writer

	recMu sync.Mutex
	rec   Recorder
	// early is the shared output read before the first recorder, until
	// EarlyMax; recorded is set once one was, and nothing is kept early
	// again after that.
	early     []earlyChunk
	earlySize int
	earlyCut  int
	recorded  bool
}

type earlyChunk struct {
	at    time.Time
	chunk []byte
}

// Join copies out to every console and what's typed on each console to in,
// until out ends. A console whose write fails gets nothing more; logf
// reports it.
func Join(out io.Reader, in io.Writer, cons []Console, logf func(string, ...any)) *Mux {
	m := &Mux{}
	for _, c := range cons {
		q := make(chan []byte, queueLen)
		m.queues = append(m.queues, q)
		m.screens = append(m.screens, IsScreen(c.Name))
		go m.write(c, q, logf)
		go typed(c, in)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := out.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				m.record(time.Now(), chunk)
				switch {
				case m.Owned():
					m.toAside(chunk)
				case m.quiet.Load():
					m.sendTo(chunk, false)
					m.toAside(chunk)
				default:
					m.sendTo(chunk, !m.held.Load())
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return m
}

// IsScreen reports whether a console is a screen (a VT: tty0, tty1 ...)
// rather than a serial line (ttyS0, ttyAMA0).
func IsScreen(name string) bool {
	n := strings.TrimPrefix(name, "tty")
	if n == name || n == "" {
		return false
	}
	return strings.Trim(n, "0123456789") == ""
}

// sendTo queues chunk for every serial line, and for every screen too
// when screens is set; a console that has fallen too far behind loses it.
func (m *Mux) sendTo(chunk []byte, screens bool) {
	for i, q := range m.queues {
		if m.screens[i] && !screens {
			continue
		}
		m.pending.Add(1)
		select {
		case q <- chunk:
		default:
			m.pending.Add(-1)
		}
	}
}

// toScreens queues chunk for the screens alone.
func (m *Mux) toScreens(chunk []byte) {
	for i, q := range m.queues {
		if !m.screens[i] {
			continue
		}
		m.pending.Add(1)
		select {
		case q <- chunk:
		default:
			m.pending.Add(-1)
		}
	}
}

// Quiet draws page on the screens and keeps the shared output (init's and
// the services' lines) off them from then on: it goes to the serial lines
// and aside. A program that owns the consoles still draws on the screens.
// Already quiet, it draws nothing.
func (m *Mux) Quiet(page []byte) {
	if m.quiet.Swap(true) && !m.held.Load() {
		return
	}
	m.toScreens(page)
}

// Loud clears the screens and lets the shared output on them again: for
// init's own screens, which ask on the console. Already loud, it clears
// nothing.
func (m *Mux) Loud() {
	q, h := m.quiet.Swap(false), m.held.Swap(false)
	if !q && !h {
		return
	}
	m.toScreens([]byte("\x1b[0m\x1b[H\x1b[2J\x1b[?25h"))
}

// Hold draws page on the screens and keeps everything else off them, the
// owner's output too: the page stays while the box stops.
func (m *Mux) Hold(page []byte) {
	m.held.Store(true)
	m.toScreens(page)
}

// SetAside sets where the shared output goes while a program owns the
// consoles or the screens are quiet; nil drops it.
func (m *Mux) SetAside(w io.Writer) {
	m.mu.Lock()
	m.aside = w
	m.mu.Unlock()
}

// SetRecord sets the recorder every chunk of the shared output also goes
// to, whoever owns the consoles: init's journal on the state volume. The
// first one gets the output kept since the start first. Nil stops
// recording (before the volume is closed).
func (m *Mux) SetRecord(r Recorder) {
	m.recMu.Lock()
	defer m.recMu.Unlock()
	if r != nil && !m.recorded {
		for _, c := range m.early {
			r.Record(c.at, c.chunk)
		}
		if m.earlyCut > 0 {
			r.Record(time.Now(), []byte(fmt.Sprintf("\nconsole: %d bytes of the boot before the state opened weren't kept\n", m.earlyCut)))
		}
		m.early, m.earlySize, m.earlyCut = nil, 0, 0
	}
	if r != nil {
		m.recorded = true
	}
	m.rec = r
}

func (m *Mux) record(at time.Time, chunk []byte) {
	m.recMu.Lock()
	defer m.recMu.Unlock()
	switch {
	case m.rec != nil:
		m.rec.Record(at, chunk)
	case m.recorded:
	case m.earlySize+len(chunk) <= EarlyMax:
		m.early = append(m.early, earlyChunk{at: at, chunk: chunk})
		m.earlySize += len(chunk)
	default:
		m.earlyCut += len(chunk)
	}
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
				m.sendTo(append([]byte(nil), buf[:n]...), !m.held.Load())
			}
			if err != nil {
				m.sendTo([]byte("\x1b[0m\r\n"), !m.held.Load())
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

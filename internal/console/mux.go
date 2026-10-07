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
	"strings"
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
// init.
type Mux struct {
	pending atomic.Int64
}

// Join copies out to every console and what's typed on each console to in,
// until out ends. A console whose write fails gets nothing more; logf
// reports it.
func Join(out io.Reader, in io.Writer, cons []Console, logf func(string, ...any)) *Mux {
	m := &Mux{}
	queues := make([]chan []byte, len(cons))
	for i, c := range cons {
		q := make(chan []byte, queueLen)
		queues[i] = q
		go m.write(c, q, logf)
		go typed(c, in)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := out.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				for _, q := range queues {
					m.pending.Add(1)
					select {
					case q <- chunk:
					default:
						m.pending.Add(-1)
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return m
}

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

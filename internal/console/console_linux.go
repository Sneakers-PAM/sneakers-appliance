// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package console

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Open opens each named console under devDir and keeps the ones that take
// writes. A serial console with no UART behind it (a VM without a serial
// port) is still in the kernel's list and still opens, but every write
// fails, so a zero-length write tells them apart.
func Open(devDir string, names []string) ([]Console, map[string]error) {
	var got []Console
	dropped := map[string]error{}
	for _, n := range names {
		p := filepath.Join(devDir, filepath.Base(n))
		fd, err := unix.Open(p, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			dropped[n] = err
			continue
		}
		if _, err := unix.Write(fd, nil); err != nil {
			_ = unix.Close(fd)
			dropped[n] = err
			continue
		}
		quietControlKeys(fd)
		got = append(got, Console{Name: n, RW: os.NewFile(uintptr(fd), p)}) // #nosec G115 -- a file descriptor
	}
	return got, dropped
}

// quietControlKeys turns off ECHOCTL on a terminal, so a cursor key
// isn't echoed as ^[[C; the line mode and the echo stay. A console that
// isn't a terminal is left alone.
func quietControlKeys(fd int) {
	tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil || tio.Lflag&unix.ECHOCTL == 0 {
		return
	}
	tio.Lflag &^= unix.ECHOCTL
	_ = unix.IoctlSetTermios(fd, unix.TCSETS, tio)
}

// Taken is init's console once Take has run.
type Taken struct {
	mux  *Mux
	out  int
	Kept []string
}

// Take makes standard input, output and error pipes joined to every
// active console that takes writes, so init and every service it starts
// (they inherit them) are seen on the screen and the serial line alike.
// It changes nothing when no console takes writes.
func Take(logf func(string, ...any)) (*Taken, map[string]error, error) {
	active, err := os.ReadFile(ActivePath)
	if err != nil {
		return nil, nil, err
	}
	cons, dropped := Open("/dev", Names(string(active)))
	if len(cons) == 0 {
		return nil, dropped, errors.New("console: no active console takes writes")
	}
	var outP, inP [2]int
	if err := unix.Pipe2(outP[:], unix.O_CLOEXEC); err != nil {
		return nil, dropped, err
	}
	if err := unix.Pipe2(inP[:], unix.O_CLOEXEC); err != nil {
		return nil, dropped, err
	}
	// dup3 without O_CLOEXEC: services inherit 1 and 2.
	for _, d := range []struct{ from, to int }{{inP[0], 0}, {outP[1], 1}, {outP[1], 2}} {
		if err := unix.Dup3(d.from, d.to, 0); err != nil {
			return nil, dropped, err
		}
	}
	_ = unix.Close(inP[0])
	_ = unix.Close(outP[1])
	return newTaken(os.NewFile(uintptr(outP[0]), "console-out"), os.NewFile(uintptr(inP[1]), "console-in"), cons, logf), dropped, nil // #nosec G115 -- file descriptors
}

// newTaken joins out, the read end of the shared output's pipe, and in,
// the write end of the input's, to cons.
func newTaken(out, in *os.File, cons []Console, logf func(string, ...any)) *Taken {
	t := &Taken{out: int(out.Fd())} // #nosec G115 -- a file descriptor
	for _, c := range cons {
		t.Kept = append(t.Kept, c.Name)
	}
	t.mux = Join(out, in, cons, logf)
	return t
}

// Flush waits, up to timeout, until what's been written to standard
// output and error is on every console: before a reboot, so the last
// lines aren't lost.
func (t *Taken) Flush(timeout time.Duration) {
	if t == nil {
		return
	}
	deadline := time.Now().Add(timeout)
	quiet := 0
	for quiet < 2 && time.Now().Before(deadline) {
		n, err := unix.IoctlGetInt(t.out, unix.TIOCINQ) // FIONREAD
		if err == nil && n == 0 && t.mux.Idle() {
			quiet++
		} else {
			quiet = 0
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Claim gives the consoles to a program: the write end of a pipe for its
// standard output. The caller closes its own copy once the program has
// started, so the claim ends with the program. What was written before
// the claim goes to the consoles first, not aside (the line saying the
// service the program waits for is ready, say).
func (t *Taken) Claim() (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	t.Flush(claimWait)
	t.mux.Attach(r)
	return w, nil
}

// SetAside sets where the shared output goes while a program owns the
// consoles.
func (t *Taken) SetAside(w io.Writer) { t.mux.SetAside(w) }

// SetRecord sets the recorder of the shared output (Mux.SetRecord).
// Nil-safe.
func (t *Taken) SetRecord(r Recorder) {
	if t != nil {
		t.mux.SetRecord(r)
	}
}

// Quiet draws page on the screens and keeps init's and the services'
// lines off them (they go to the serial lines and aside). Nil-safe.
func (t *Taken) Quiet(page []byte) {
	if t != nil {
		t.mux.Quiet(page)
	}
}

// Loud clears the screens for init's own screens, which ask on the
// console, once the lines written so far have gone their way. Nil-safe.
func (t *Taken) Loud() {
	if t == nil {
		return
	}
	t.Flush(loudWait)
	t.mux.Loud()
}

// Hold draws page on the screens and keeps everything else off them until
// the box stops. Nil-safe.
func (t *Taken) Hold(page []byte) {
	if t != nil {
		t.mux.Hold(page)
	}
}

// loudWait bounds how long Loud waits for the quiet lines to go their way.
const loudWait = 500 * time.Millisecond

// claimWait bounds how long a claim waits for the lines written before it
// to reach the consoles.
const claimWait = 500 * time.Millisecond

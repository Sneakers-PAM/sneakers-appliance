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
	t := &Taken{out: outP[0]}
	for _, c := range cons {
		t.Kept = append(t.Kept, c.Name)
	}
	t.mux = Join(os.NewFile(uintptr(outP[0]), "console-out"), os.NewFile(uintptr(inP[1]), "console-in"), cons, logf) // #nosec G115 -- file descriptors
	return t, dropped, nil
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
// started, so the claim ends with the program.
func (t *Taken) Claim() (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	t.mux.Attach(r)
	return w, nil
}

// SetAside sets where the shared output goes while a program owns the
// consoles.
func (t *Taken) SetAside(w io.Writer) { t.mux.SetAside(w) }

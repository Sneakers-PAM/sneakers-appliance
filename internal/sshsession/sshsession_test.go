// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshsession_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshsession"
)

const (
	shell = "/usr/bin/sneakers-shell"
	btime = 1_790_000_000
)

// fakeProc is a /proc tree with only the files the scanner reads.
type fakeProc struct {
	t    *testing.T
	root string
	mu   sync.Mutex
	sent []string
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	f := &fakeProc{t: t, root: t.TempDir()}
	f.write("stat", fmt.Sprintf("cpu  1 2 3 4\nbtime %d\nprocesses 10\n", btime))
	return f
}

func (f *fakeProc) write(name, body string) {
	f.t.Helper()
	p := filepath.Join(f.root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// process adds pid running exe as uid, started ticks after boot.
func (f *fakeProc) process(pid, ppid, uid int, exe string, ticks uint64, env ...string) {
	f.t.Helper()
	dir := fmt.Sprintf("%d", pid)
	// The command name has a space and a parenthesis, as a hostile one may.
	f.write(dir+"/stat", fmt.Sprintf("%d (odd) name) S %d %d %d 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 %d 1000 100", pid, ppid, pid, pid, ticks))
	f.write(dir+"/status", fmt.Sprintf("Name:\todd\nPid:\t%d\nUid:\t%d\t%d\t%d\t%d\n", pid, uid, uid, uid, uid))
	f.write(dir+"/environ", strings.Join(env, "\x00")+"\x00")
	if err := os.Symlink(exe, filepath.Join(f.root, dir, "exe")); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) signal(pid int, sig syscall.Signal) error {
	f.mu.Lock()
	f.sent = append(f.sent, fmt.Sprintf("%d %s", pid, sig))
	f.mu.Unlock()
	return os.RemoveAll(filepath.Join(f.root, fmt.Sprintf("%d", pid)))
}

func (f *fakeProc) signals() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

func (f *fakeProc) scanner() *sshsession.Proc {
	users := map[int]string{1001: "alice", 1002: "bob"}
	return &sshsession.Proc{
		Root: f.root, Shell: shell, Signal: f.signal, Wait: time.Second,
		User: func(uid int) (string, error) {
			if n, ok := users[uid]; ok {
				return n, nil
			}
			return "", errors.New("no such user")
		},
	}
}

func TestListFindsEveryClosedShellAndNothingElse(t *testing.T) {
	f := newFakeProc(t)
	f.process(90, 80, 1001, "/usr/sbin/sshd-session", 12000)
	f.process(100, 90, 1001, shell, 12345, "USER=alice", "SSH_CONNECTION=192.0.2.50 51000 192.0.2.10 22")
	f.process(200, 190, 1002, shell, 50000, "SSH_CONNECTION=2001:db8::7 40000 2001:db8::1 22")
	// An elevated shell, a program that names itself sneakers-shell and a
	// shell already deleted from disk are not closed-shell sessions here,
	// or not this one's.
	f.process(300, 290, 0, "/usr/libexec/sneakers-elevated", 60000, "SSH_CONNECTION=192.0.2.51 1 192.0.2.10 22")
	f.process(301, 1, 1001, "/usr/bin/sneakers-shell-not", 60000, "SSH_CONNECTION=192.0.2.52 1 192.0.2.10 22")
	f.write("self/stat", "not a pid")
	got, err := f.scanner().List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("sessions %+v", got)
	}
	a, b := got[0], got[1]
	if a.ID != "ssh-100-12345" || a.PID != 100 || a.Admin != "alice" || a.Source != "192.0.2.50" || !a.Started.Equal(time.Unix(btime+123, 450_000_000)) {
		t.Fatalf("first %+v", a)
	}
	if b.ID != "ssh-200-50000" || b.Admin != "bob" || b.Source != "2001:db8::7" {
		t.Fatalf("second %+v", b)
	}
}

func TestListNamesAnUnknownUIDByNumber(t *testing.T) {
	f := newFakeProc(t)
	f.process(100, 90, 4242, shell, 1, "SSH_CONNECTION=192.0.2.50 51000 192.0.2.10 22")
	got, err := f.scanner().List()
	if err != nil || len(got) != 1 || got[0].Admin != "uid 4242" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestEndHangsUpTheShellAndItsSSHConnection(t *testing.T) {
	f := newFakeProc(t)
	f.process(90, 80, 1001, "/usr/sbin/sshd-session", 12000)
	f.process(100, 90, 1001, shell, 12345, "SSH_CONNECTION=192.0.2.50 51000 192.0.2.10 22")
	s, err := f.scanner().End("ssh-100-12345")
	if err != nil {
		t.Fatal(err)
	}
	if s.Admin != "alice" || s.Source != "192.0.2.50" {
		t.Fatalf("ended %+v", s)
	}
	if got := f.signals(); len(got) != 2 || got[0] != "100 hangup" || got[1] != "90 terminated" {
		t.Fatalf("signals %v", got)
	}
	if left, _ := f.scanner().List(); len(left) != 0 {
		t.Fatalf("still listed %+v", left)
	}
}

func TestEndLeavesAParentThatIsNotSSHD(t *testing.T) {
	f := newFakeProc(t)
	f.process(90, 1, 0, "/usr/bin/sneakers-init", 1)
	f.process(100, 90, 1001, shell, 12345)
	if _, err := f.scanner().End("ssh-100-12345"); err != nil {
		t.Fatal(err)
	}
	if got := f.signals(); len(got) != 1 || got[0] != "100 hangup" {
		t.Fatalf("signals %v", got)
	}
}

func TestEndRefusesAReusedOrUnknownID(t *testing.T) {
	f := newFakeProc(t)
	f.process(100, 90, 1001, shell, 99999)
	f.process(300, 290, 0, "/usr/libexec/sneakers-elevated", 1)
	for _, id := range []string{"ssh-100-12345", "ssh-300-1", "ssh-7-1", "ssh-x-1", "web-100-12345", ""} {
		if _, err := f.scanner().End(id); !errors.Is(err, sshsession.ErrNotFound) {
			t.Errorf("End(%q) = %v", id, err)
		}
	}
	if got := f.signals(); len(got) != 0 {
		t.Fatalf("signals %v", got)
	}
}

func TestEndKillsAShellThatIgnoresTheHangup(t *testing.T) {
	f := newFakeProc(t)
	f.process(100, 90, 1001, shell, 12345)
	p := f.scanner()
	p.Wait = 100 * time.Millisecond
	p.Signal = func(pid int, sig syscall.Signal) error {
		f.mu.Lock()
		f.sent = append(f.sent, fmt.Sprintf("%d %s", pid, sig))
		f.mu.Unlock()
		if sig == syscall.SIGKILL {
			return os.RemoveAll(filepath.Join(f.root, fmt.Sprintf("%d", pid)))
		}
		return nil
	}
	if _, err := p.End("ssh-100-12345"); err != nil {
		t.Fatal(err)
	}
	if got := f.signals(); len(got) != 2 || got[1] != "100 killed" {
		t.Fatalf("signals %v", got)
	}
}

// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package sshsession lists the admins' live SSH logins to the closed shell
// and ends them. The process table is the record: every sneakers-shell
// process sshd started is one session, so the list can't drift from what
// is running. accessd uses it as root, which can read every process's
// environment.
package sshsession

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ShellPath is where the image installs the closed shell.
const ShellPath = "/usr/bin/sneakers-shell"

// clockTicks is USER_HZ, the unit of a process's start time in
// /proc/<pid>/stat. Linux fixes it at 100 on every architecture.
const clockTicks = 100

// ErrNotFound is an id that names no live session.
var ErrNotFound = errors.New("there is no such SSH session")

// Session is one admin's SSH login to the closed shell.
type Session struct {
	// ID is "ssh-<pid>-<start ticks>": the start time keeps a reused pid
	// from naming a later process.
	ID      string
	PID     int
	Admin   string
	Source  string
	Started time.Time
}

// Proc reads the sessions from a /proc tree.
type Proc struct {
	// Root defaults to /proc and Shell to ShellPath.
	Root, Shell string
	// User names a uid; it defaults to the system's account database.
	User func(uid int) (string, error)
	// Signal defaults to kill(2).
	Signal func(pid int, sig syscall.Signal) error
	// Wait is how long End lets a shell go after the hang-up before it
	// kills it; the default is five seconds.
	Wait time.Duration
}

func (p *Proc) root() string {
	if p.Root == "" {
		return "/proc"
	}
	return p.Root
}

func (p *Proc) shell() string {
	if p.Shell == "" {
		return ShellPath
	}
	return p.Shell
}

func (p *Proc) user(uid int) string {
	lookup := p.User
	if lookup == nil {
		lookup = func(uid int) (string, error) {
			u, err := user.LookupId(strconv.Itoa(uid))
			if err != nil {
				return "", err
			}
			return u.Username, nil
		}
	}
	if name, err := lookup(uid); err == nil && name != "" {
		return name
	}
	return "uid " + strconv.Itoa(uid)
}

func (p *Proc) signal(pid int, sig syscall.Signal) error {
	if p.Signal != nil {
		return p.Signal(pid, sig)
	}
	return unix.Kill(pid, sig)
}

func (p *Proc) wait() time.Duration {
	if p.Wait <= 0 {
		return 5 * time.Second
	}
	return p.Wait
}

// List returns every live closed-shell session, oldest first.
func (p *Proc) List() ([]Session, error) {
	boot, err := p.bootTime()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(p.root())
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if s, ok := p.session(pid, boot); ok {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b Session) int {
		if c := a.Started.Compare(b.Started); c != 0 {
			return c
		}
		return a.PID - b.PID
	})
	return out, nil
}

// End hangs up the session's shell and its sshd connection, waits for the
// shell to go and kills it if it doesn't. It returns the session it ended.
func (p *Proc) End(id string) (Session, error) {
	pid, ticks, ok := parseID(id)
	if !ok {
		return Session{}, ErrNotFound
	}
	boot, err := p.bootTime()
	if err != nil {
		return Session{}, err
	}
	s, ok := p.session(pid, boot)
	if !ok || s.ID != id {
		return Session{}, ErrNotFound
	}
	st, err := p.stat(pid)
	if err != nil {
		return Session{}, ErrNotFound
	}
	if err := p.signal(pid, syscall.SIGHUP); err != nil && !errors.Is(err, syscall.ESRCH) {
		return s, fmt.Errorf("sshsession: hang up %d: %w", pid, err)
	}
	// The shell's parent is sshd's process for this connection; ending it
	// closes the connection, with every channel and forwarding on it.
	if st.ppid > 1 && p.isSSHD(st.ppid) {
		if err := p.signal(st.ppid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return s, fmt.Errorf("sshsession: end sshd %d: %w", st.ppid, err)
		}
	}
	if p.gone(pid, ticks, p.wait()) {
		return s, nil
	}
	if err := p.signal(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return s, fmt.Errorf("sshsession: kill %d: %w", pid, err)
	}
	if p.gone(pid, ticks, time.Second) {
		return s, nil
	}
	return s, fmt.Errorf("sshsession: %s is still running after SIGKILL", id)
}

func parseID(id string) (int, int64, bool) {
	rest, ok := strings.CutPrefix(id, "ssh-")
	if !ok {
		return 0, 0, false
	}
	a, b, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, 0, false
	}
	pid, err := strconv.Atoi(a)
	if err != nil || pid <= 0 {
		return 0, 0, false
	}
	ticks, err := strconv.ParseInt(b, 10, 64)
	if err != nil || ticks < 0 {
		return 0, 0, false
	}
	return pid, ticks, true
}

// gone waits up to d for pid (started at ticks) to exit; a zombie counts
// as gone.
func (p *Proc) gone(pid int, ticks int64, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		st, err := p.stat(pid)
		if err != nil || st.ticks != ticks || st.state == 'Z' || st.state == 'X' {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (p *Proc) session(pid int, boot time.Time) (Session, bool) {
	if exe, err := p.exe(pid); err != nil || exe != p.shell() {
		return Session{}, false
	}
	st, err := p.stat(pid)
	if err != nil || st.state == 'Z' || st.state == 'X' {
		return Session{}, false
	}
	uid, err := p.uid(pid)
	if err != nil {
		return Session{}, false
	}
	started := boot.Add(time.Duration(st.ticks) * time.Second / clockTicks)
	return Session{
		ID:      fmt.Sprintf("ssh-%d-%d", pid, st.ticks),
		PID:     pid,
		Admin:   p.user(uid),
		Source:  p.source(pid),
		Started: started,
	}, true
}

func (p *Proc) path(pid int, name string) string {
	return filepath.Join(p.root(), strconv.Itoa(pid), name)
}

func (p *Proc) exe(pid int) (string, error) {
	exe, err := os.Readlink(p.path(pid, "exe"))
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(exe, " (deleted)"), nil
}

func (p *Proc) isSSHD(pid int) bool {
	exe, err := p.exe(pid)
	if err != nil {
		return false
	}
	switch filepath.Base(exe) {
	case "sshd", "sshd-session":
		return true
	}
	return false
}

type procStat struct {
	state byte
	ppid  int
	ticks int64
}

// stat reads /proc/<pid>/stat. The command name is in parentheses and may
// hold spaces and parentheses itself, so the fields after it are found
// from the last ')'.
func (p *Proc) stat(pid int) (procStat, error) {
	b, err := os.ReadFile(p.path(pid, "stat")) // #nosec G304 -- a procfs file
	if err != nil {
		return procStat{}, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return procStat{}, fmt.Errorf("sshsession: %d: stat has no command name", pid)
	}
	// After the name: state(3) ppid(4) ... starttime(22).
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 || len(f[0]) != 1 {
		return procStat{}, fmt.Errorf("sshsession: %d: stat is short", pid)
	}
	ppid, err := strconv.Atoi(f[1])
	if err != nil {
		return procStat{}, err
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return procStat{}, err
	}
	return procStat{state: f[0][0], ppid: ppid, ticks: ticks}, nil
}

func (p *Proc) uid(pid int) (int, error) {
	b, err := os.ReadFile(p.path(pid, "status")) // #nosec G304 -- a procfs file
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			break
		}
		return strconv.Atoi(f[0])
	}
	return 0, fmt.Errorf("sshsession: %d: status has no Uid", pid)
}

// source is the client address from the SSH_CONNECTION sshd gave the
// shell; empty when it's missing.
func (p *Proc) source(pid int) string {
	b, err := os.ReadFile(p.path(pid, "environ")) // #nosec G304 -- a procfs file
	if err != nil {
		return ""
	}
	for kv := range bytes.SplitSeq(b, []byte{0}) {
		if v, ok := bytes.CutPrefix(kv, []byte("SSH_CONNECTION=")); ok {
			if f := strings.Fields(string(v)); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

func (p *Proc) bootTime() (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(p.root(), "stat")) // #nosec G304 -- a procfs file
	if err != nil {
		return time.Time{}, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(sec, 0), nil
		}
	}
	return time.Time{}, errors.New("sshsession: /proc/stat has no btime")
}

// Source is the SSH client address of any process sshd started, such as
// an elevated shell; empty when the process is gone or has none.
func (p *Proc) Source(pid int) string { return p.source(pid) }

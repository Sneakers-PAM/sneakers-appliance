// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshdrun"
)

// fakeSshd records the signals sshd-run sends and ends when told.
type fakeSshd struct {
	mu      sync.Mutex
	config  string
	signals []os.Signal
	done    chan error
}

func (f *fakeSshd) Signal(s os.Signal) error {
	f.mu.Lock()
	f.signals = append(f.signals, s)
	f.mu.Unlock()
	if s == syscall.SIGTERM {
		f.done <- nil
	}
	return nil
}

func (f *fakeSshd) Wait() error { return <-f.done }

func (f *fakeSshd) hups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.signals {
		if s == syscall.SIGHUP {
			n++
		}
	}
	return n
}

type memAudit struct {
	mu      sync.Mutex
	entries []osaudit.Entry
}

func (m *memAudit) Append(e osaudit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

func (m *memAudit) all() []osaudit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]osaudit.Entry(nil), m.entries...)
}

type rig struct {
	t      *testing.T
	state  string
	run    string
	addrs  []netip.Addr
	mu     sync.Mutex
	check  error
	sshd   *fakeSshd
	audit  *memAudit
	reload chan struct{}
	runErr chan error
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, state: t.TempDir(), run: t.TempDir(), addrs: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		audit: &memAudit{}, reload: make(chan struct{}, 1)}
	return r
}

func (r *rig) setAddrs(a ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addrs = nil
	for _, s := range a {
		r.addrs = append(r.addrs, netip.MustParseAddr(s))
	}
}

func (r *rig) failCheck(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.check = err
}

func (r *rig) options(mode sshdrun.Mode) sshdrun.Options {
	p := sshconfig.DefaultPaths()
	p.ConfigDir = filepath.Join(r.run, "ssh")
	return sshdrun.Options{
		Mode: mode, Paths: p, StateDir: r.state, AccountsDir: filepath.Join(r.run, "accounts"),
		Addresses: func(context.Context) ([]netip.Addr, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if len(r.addrs) == 0 {
				return nil, errors.New("no management address yet")
			}
			return append([]netip.Addr(nil), r.addrs...), nil
		},
		Check: func(string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.check
		},
		Start: func(config string) (sshdrun.Daemon, error) {
			d := &fakeSshd{config: config, done: make(chan error, 1)}
			r.mu.Lock()
			r.sshd = d
			r.mu.Unlock()
			return d, nil
		},
		Audit:       r.audit,
		AddressWait: 50 * time.Millisecond,
	}
}

// start prepares and runs sshd-run in mode; it stops with the test.
func (r *rig) start(mode sshdrun.Mode) *sshdrun.Runner {
	r.t.Helper()
	run := sshdrun.New(r.options(mode))
	ctx, cancel := context.WithCancel(context.Background())
	if err := run.Prepare(ctx); err != nil {
		cancel()
		r.t.Fatal(err)
	}
	r.runErr = make(chan error, 1)
	go func() { r.runErr <- run.Run(ctx, r.reload) }()
	r.t.Cleanup(func() {
		cancel()
		select {
		case <-r.runErr:
		case <-time.After(5 * time.Second):
			r.t.Error("Run didn't stop")
		}
	})
	waitFor(r.t, func() bool { return r.daemon() != nil })
	return run
}

func (r *rig) daemon() *fakeSshd {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sshd
}

func (r *rig) config() string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.run, "ssh", "sshd_config"))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *rig) kick(run *sshdrun.Runner) {
	r.t.Helper()
	before := run.Reloads()
	r.reload <- struct{}{}
	waitFor(r.t, func() bool { return run.Reloads() > before })
}

// writeStore writes the access store with owners holding a key each.
func (r *rig) writeStore(owners ...string) {
	r.t.Helper()
	st := access.State{NextUID: access.FirstUID}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for _, n := range owners {
		a := st.AddAdmin(n, access.RoleOwner, "console", now)
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			r.t.Fatal(err)
		}
		sp, err := ssh.NewPublicKey(pub)
		if err != nil {
			r.t.Fatal(err)
		}
		k, err := access.ParseLoginKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))))
		if err != nil {
			r.t.Fatal(err)
		}
		a.Keys = append(a.Keys, access.AdminKey{Key: k, Added: now, AddedBy: "console", Via: access.ViaEnrol})
	}
	b, err := json.Marshal(st)
	if err != nil {
		r.t.Fatal(err)
	}
	dir := filepath.Join(r.state, "access")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, access.FileName), b, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

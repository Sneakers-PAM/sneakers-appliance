// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshdrun"
)

// sshd stays off until the first admin exists.
func TestWithoutAnAdminWhoCanSignInSshdIsRefused(t *testing.T) {
	r := newRig(t)
	err := sshdrun.New(r.options()).Prepare(context.Background())
	if !codes.Is(err, codes.AccessNoAdmin) {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.run, "ssh", "sshd_config")); !os.IsNotExist(err) {
		t.Fatalf("a config was rendered: %v", err)
	}
	r.writeStore("alice")
	if err := sshdrun.New(r.options()).Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := r.config(); !strings.Contains(c, "AllowUsers alice\n") {
		t.Fatalf("with an admin:\n%s", c)
	}
}

func TestRunStartsSshdOnTheCheckedConfig(t *testing.T) {
	r := newRig(t)
	r.writeStore("alice")
	r.start()
	if r.daemon().config != filepath.Join(r.run, "ssh", "sshd_config") {
		t.Fatalf("sshd started on %q", r.daemon().config)
	}
}

// A SIGHUP from accessd renders again; sshd is told only when the config
// it runs differs, and only after sshd -t passed.
func TestReloadSignalsSshdOnlyAfterTheCheckPasses(t *testing.T) {
	r := newRig(t)
	r.writeStore("alice")
	run := r.start()
	r.kick(run)
	if n := r.daemon().hups(); n != 0 {
		t.Fatalf("%d SIGHUPs for an unchanged config", n)
	}
	r.writeStore("alice", "bob")
	r.kick(run)
	if n := r.daemon().hups(); n != 1 || !strings.Contains(r.config(), "AllowUsers alice bob\n") {
		t.Fatalf("%d SIGHUPs, config:\n%s", n, r.config())
	}
	before := r.config()
	r.failCheck(errors.New("sshd -t: /run/sneakers/ssh.next/sshd_config line 3: Bad configuration option"))
	r.writeStore("alice", "bob", "carol")
	r.kick(run)
	if n := r.daemon().hups(); n != 1 {
		t.Fatalf("%d SIGHUPs after a refused render", n)
	}
	if r.config() != before {
		t.Fatalf("a refused render reached the live config:\n%s", r.config())
	}
	es := r.audit.all()
	if len(es) != 1 || es[0].Action != "sshd.config" || es[0].Outcome != "refused" || !strings.Contains(es[0].Detail["error"], "Bad configuration option") {
		t.Fatalf("audit %+v", es)
	}
}

// accessd swaps in a new config itself and then signals: sshd-run's own
// render matches, but sshd still runs the old one, so it's told.
func TestAConfigAccessdInstalledIsPassedOn(t *testing.T) {
	r := newRig(t)
	r.writeStore("alice")
	run := r.start()
	r.writeStore("alice", "bob")
	opts := r.options()
	in, err := run.Input(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sshconfig.Install(in, opts.Check); err != nil {
		t.Fatal(err)
	}
	r.kick(run)
	if n := r.daemon().hups(); n != 1 {
		t.Fatalf("%d SIGHUPs", n)
	}
}

func TestAnAddressChangeRebinds(t *testing.T) {
	r := newRig(t)
	r.writeStore("alice")
	run := r.start()
	r.setAddrs("192.0.2.20", "2001:db8::20")
	r.kick(run)
	c := r.config()
	if r.daemon().hups() != 1 || !strings.Contains(c, "ListenAddress 192.0.2.20:22") || !strings.Contains(c, "ListenAddress [2001:db8::20]:22") || strings.Contains(c, "192.0.2.10") {
		t.Fatalf("%d SIGHUPs, config:\n%s", r.daemon().hups(), c)
	}
}

// With no management address yet sshd-run waits for one instead of
// rendering a config sshd can't listen with.
func TestPrepareWaitsForAnAddress(t *testing.T) {
	r := newRig(t)
	r.writeStore("alice")
	r.setAddrs()
	go func() {
		time.Sleep(200 * time.Millisecond)
		r.setAddrs("192.0.2.30")
	}()
	if err := sshdrun.New(r.options()).Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.config(), "ListenAddress 192.0.2.30:22") {
		t.Fatalf("config:\n%s", r.config())
	}
}

func TestStoppingStopsSshd(t *testing.T) {
	r := newRig(t)
	r.writeStore("alice")
	run := sshdrun.New(r.options())
	ctx, cancel := context.WithCancel(context.Background())
	if err := run.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- run.Run(ctx, nil) }()
	waitFor(t, func() bool { return r.daemon() != nil })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't stop")
	}
	r.daemon().mu.Lock()
	defer r.daemon().mu.Unlock()
	if len(r.daemon().signals) == 0 || r.daemon().signals[len(r.daemon().signals)-1] != syscall.SIGTERM {
		t.Fatalf("signals %v", r.daemon().signals)
	}
}

func TestSshdExitingEndsRun(t *testing.T) {
	r := newRig(t)
	r.writeStore("alice")
	run := sshdrun.New(r.options())
	if err := run.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- run.Run(context.Background(), nil) }()
	waitFor(t, func() bool { return r.daemon() != nil })
	r.daemon().done <- errors.New("exit status 255")
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "255") {
			t.Fatalf("err %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't end with sshd")
	}
}

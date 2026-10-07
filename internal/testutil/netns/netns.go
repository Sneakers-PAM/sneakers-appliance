// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package netns builds small network labs for tests: network namespaces
// joined by veth pairs, with the test binary itself run inside one as a
// helper process, so the code under test touches only the lab's
// interfaces and never the host's. It needs root (CAP_NET_ADMIN) and
// iproute2's ip; without them the tests skip, or fail when
// SNEAKERS_REQUIRE_NETNS is set, as CI's root step does.
package netns

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// helperEnv names the helper a re-executed test binary runs.
const helperEnv = "SNEAKERS_NETNS_HELPER"

// Require skips t unless it can build a lab.
func Require(t testing.TB) {
	t.Helper()
	var why string
	if os.Geteuid() != 0 {
		why = "network namespace tests need root"
	} else if _, err := exec.LookPath("ip"); err != nil {
		why = "network namespace tests need iproute2's ip"
	}
	if why == "" {
		return
	}
	if os.Getenv("SNEAKERS_REQUIRE_NETNS") != "" {
		t.Fatal(why + " and SNEAKERS_REQUIRE_NETNS is set")
	}
	t.Skip(why)
}

// RunHelpers is for TestMain: when this process is a helper, it runs the
// named helper and exits with its result; otherwise it returns and the
// tests run.
func RunHelpers(helpers map[string]func() error) {
	name := os.Getenv(helperEnv)
	if name == "" {
		return
	}
	fn, ok := helpers[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "netns: no helper %q\n", name)
		os.Exit(2)
	}
	if err := fn(); err != nil {
		fmt.Fprintf(os.Stderr, "netns: helper %s: %v\n", name, err)
		os.Exit(1)
	}
	os.Exit(0)
}

var counter atomic.Int32

// Lab is a set of namespaces that disappear with the test.
type Lab struct {
	t  testing.TB
	id string
}

// New starts an empty lab.
func New(t testing.TB) *Lab {
	t.Helper()
	Require(t)
	return &Lab{t: t, id: fmt.Sprintf("%d%d", os.Getpid()%10000, counter.Add(1))}
}

// NS creates a namespace with its loopback up and returns its name.
func (l *Lab) NS(role string) string {
	l.t.Helper()
	name := "snk" + role + l.id
	l.run("ip", "netns", "add", name)
	l.t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() }) // #nosec G204 -- test-only
	l.IP(name, "link", "set", "lo", "up")
	return name
}

// Link joins namespace a's interface aIf to b's bIf with a veth pair, both
// up.
func (l *Lab) Link(a, aIf, b, bIf string) {
	l.t.Helper()
	tmp := fmt.Sprintf("snkv%s%d", l.id, counter.Add(1))
	l.run("ip", "link", "add", tmp+"a", "type", "veth", "peer", "name", tmp+"b")
	l.run("ip", "link", "set", tmp+"a", "netns", a)
	l.run("ip", "link", "set", tmp+"b", "netns", b)
	l.IP(a, "link", "set", tmp+"a", "name", aIf)
	l.IP(b, "link", "set", tmp+"b", "name", bIf)
	l.IP(a, "link", "set", aIf, "up")
	l.IP(b, "link", "set", bIf, "up")
}

// IP runs ip -n ns args.
func (l *Lab) IP(ns string, args ...string) string {
	l.t.Helper()
	return l.run("ip", append([]string{"-n", ns}, args...)...)
}

// Sysctl sets key=value inside ns.
func (l *Lab) Sysctl(ns, key, value string) {
	l.t.Helper()
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	l.run("ip", "netns", "exec", ns, "sh", "-c", "echo "+value+" > "+path)
}

func (l *Lab) run(name string, args ...string) string {
	l.t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- test-only, fixed tools
	if err != nil {
		l.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// Helper is a helper process: the test binary run as helper name inside a
// namespace.
type Helper struct {
	cmd    *exec.Cmd
	out    *syncBuffer
	done   chan struct{}
	err    error
	cancel context.CancelFunc
}

// Start runs helper name inside ns with env added; it is killed when the
// test ends.
func (l *Lab) Start(ns, name string, env ...string) *Helper {
	l.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, os.Args[0], "-test.run=^$") // #nosec G204 G702 -- test-only: the test binary itself
	cmd.Env = append(append(os.Environ(), helperEnv+"="+name), env...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	h := &Helper{cmd: cmd, out: &syncBuffer{}, done: make(chan struct{}), cancel: cancel}
	cmd.Stdout, cmd.Stderr = h.out, h.out
	if err := cmd.Start(); err != nil {
		cancel()
		l.t.Fatal(err)
	}
	go func() { h.err = cmd.Wait(); close(h.done) }()
	l.t.Cleanup(func() {
		h.Stop()
		if l.t.Failed() {
			l.t.Logf("helper %s in %s:\n%s", name, ns, h.out.String())
		}
	})
	return h
}

// Run runs helper name inside ns to completion and returns its output.
func (l *Lab) Run(ns, name string, env ...string) (string, error) {
	l.t.Helper()
	h := l.Start(ns, name, env...)
	select {
	case <-h.done:
	case <-time.After(2 * time.Minute):
		h.Stop()
		return h.out.String(), fmt.Errorf("helper %s didn't finish", name)
	}
	return h.out.String(), h.err
}

// Stop ends the helper (SIGINT, then SIGKILL) and waits for it.
func (h *Helper) Stop() {
	h.cancel()
	<-h.done
}

// Err is how the helper ended, once Exited.
func (h *Helper) Err() error {
	if !h.Exited() {
		return nil
	}
	return h.err
}

// Output is what the helper printed so far.
func (h *Helper) Output() string { return h.out.String() }

// Exited reports whether the helper has ended.
func (h *Helper) Exited() bool {
	select {
	case <-h.done:
		return true
	default:
		return false
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshsession_test

import (
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshsession"
)

// A real process running as the closed shell is listed from the live /proc
// and really ends.
func TestALiveShellIsListedAndEnds(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	// /proc/<pid>/exe holds the resolved path, so the temp dir is resolved
	// too.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shellCopy := filepath.Join(dir, "sneakers-shell")
	copyFile(t, sleep, shellCopy)
	cmd := exec.Command(shellCopy, "300") // #nosec G204 -- test-only
	cmd.Env = []string{"SSH_CONNECTION=192.0.2.60 50123 192.0.2.10 22"}
	before := time.Now().Add(-2 * time.Second)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })

	p := &sshsession.Proc{Shell: shellCopy, Wait: 5 * time.Second}
	got, err := p.List()
	if err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PID != cmd.Process.Pid || got[0].Admin != me.Username || got[0].Source != "192.0.2.60" {
		t.Fatalf("sessions %+v", got)
	}
	if got[0].Started.Before(before) || got[0].Started.After(time.Now().Add(2*time.Second)) {
		t.Fatalf("started %v", got[0].Started)
	}
	if _, err := p.End(got[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the shell is still running")
	}
	if left, err := p.List(); err != nil || len(left) != 0 {
		t.Fatalf("still listed %+v %v", left, err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from) // #nosec G304 -- test-only
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY, 0o755) // #nosec G302 G304 -- test-only executable
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

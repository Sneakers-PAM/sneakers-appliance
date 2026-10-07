// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

// ExecRunner runs real programs, with their output on init's console.
type ExecRunner struct{}

// Start starts argv.
func (ExecRunner) Start(argv []string) (Process, error) {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- argv comes from the read-only service table
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProcess{cmd}, nil
}

// StartAs starts argv under uid and gid, with no supplementary groups.
func (ExecRunner) StartAs(argv []string, uid, gid uint32) (Process, error) {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- argv comes from the read-only service table
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProcess{cmd}, nil
}

// Run runs argv to completion.
func (ExecRunner) Run(ctx context.Context, argv []string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- as above
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// Exists reports whether path exists.
func (ExecRunner) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type execProcess struct{ cmd *exec.Cmd }

func (p execProcess) Wait() error                { return p.cmd.Wait() }
func (p execProcess) Signal(sig os.Signal) error { return p.cmd.Process.Signal(sig) }

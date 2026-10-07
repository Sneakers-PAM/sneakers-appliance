// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun

import (
	"io"
	"os"
	"os/exec"
)

// Exec starts the pinned sshd in the foreground on a config, logging to
// out: sshd -D -e -f <config>.
func Exec(sshd string, out io.Writer) func(config string) (Daemon, error) {
	return func(config string) (Daemon, error) {
		cmd := exec.Command(sshd, "-D", "-e", "-f", config) // #nosec G204 -- the pinned sshd on the config sshd-run installed
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return proc{cmd}, nil
	}
}

type proc struct{ cmd *exec.Cmd }

func (p proc) Signal(s os.Signal) error { return p.cmd.Process.Signal(s) }
func (p proc) Wait() error              { return p.cmd.Wait() }

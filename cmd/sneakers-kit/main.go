// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-kit verifies an org-signed appliance release and builds
// install media from it. It never signs anything and holds no private key.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ova"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/qcow2"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: it returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	// The pins come first: a kit that can't say which keys it trusts must
	// not verify or build anything.
	pins, err := release.Load()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sneakers-kit:", codes.Describe(err))
		return 2
	}
	root := newRoot(pins, stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		_, _ = fmt.Fprintln(stderr, "sneakers-kit:", codes.Describe(err))
		return 1
	}
	return 0
}

func newRoot(pins release.Pins, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "sneakers-kit",
		Short:         "Verify an org-signed appliance release and build install media from it",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newVersionCmd(pins), newVerifyCmd(pins), newBuildCmd(pins, writers()), newBackupCmd())
	return root
}

// writers are the output formats this kit builds.
func writers() kitout.Writers {
	return kitout.NewWriters(disk.Raw{}, ova.OVA{}, qcow2.QCOW2{})
}

// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-enrol-keys is sshd's AuthorizedKeysCommand for the enrol
// account (sneakers-enrol-keys %f %k %t), run as sshkeys: it prints the
// offered key back, restricted, so any key of an accepted type
// authenticates as enrol. The account exists only while an enrolment
// window is open, and sneakers-enrol then needs the code and the console's
// yes before anything is stored.
package main

import (
	"fmt"
	"os"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
)

func main() {
	if len(os.Args) != 4 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: sneakers-enrol-keys <fingerprint> <key> <type>")
		os.Exit(1)
	}
	line, err := enrol.AuthorizedLine(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-enrol-keys:", err)
		return
	}
	_, _ = fmt.Fprintln(os.Stdout, line)
}

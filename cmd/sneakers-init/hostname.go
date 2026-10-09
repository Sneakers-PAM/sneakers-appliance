// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxname"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// stateRoot is the state volume's /var/lib/sneakers.
const stateRoot = "/var/lib/sneakers"

// bootHostname is the kernel host name init sets once the state is open,
// before any service starts: the configured name, else the box's own name.
// netd keeps it current after that (the DHCP name, a changed setting).
func bootHostname(stateDir string) (string, error) {
	own, err := boxname.Ensure(stateDir)
	if err != nil {
		return "", err
	}
	if s, err := network.ReadFile(filepath.Join(stateDir, "settings", "network.yaml")); err == nil && s.Hostname != "" {
		return s.Hostname, nil
	}
	return own, nil
}

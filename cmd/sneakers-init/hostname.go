// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxname"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxvalues"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
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

// webServedFile is where sneakers-osadmin records the pages it serves
// (osadmin.Paths.OwnDir and osadmin.WebServedFile).
func webServedFile(stateDir string) string {
	return filepath.Join(stateDir, "osadmin", "web-served.json")
}

// recordBoxVersions records the box's Base OS and Base Web versions for
// the product's stacks, before any service starts, so the k0s start that
// follows a Base OS update puts the new versions in place. The Base Web is
// the slot osadmin last served; built-in pages, or none recorded yet, carry
// the Base OS's own version.
func recordBoxVersions(stateDir, osVersion string) error {
	web := webslots.ServedVersion(webServedFile(stateDir), osVersion)
	return boxvalues.RecordVersions(filepath.Join(stateDir, "platform"), osVersion, web)
}

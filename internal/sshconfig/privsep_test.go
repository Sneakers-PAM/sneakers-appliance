// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshconfig_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
)

// sshd won't start, or check a config, without its privilege-separation
// directory, which lives on /run and so is made on every boot.
func TestEnsurePrivsepDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run", "sshd-empty")
	for range 2 {
		if err := sshconfig.EnsurePrivsepDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
		t.Fatalf("%v %v", fi, err)
	}
}

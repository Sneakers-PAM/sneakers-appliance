// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package custody_test is the image suite's key-file custody on the first
// lab target's hardware, firmware without Secure Boot and no TPM: first
// boot formats and mounts the state and accessd stays up, the next boot
// reads the mode back from the LUKS2 header, and a wiped key file stops the
// boot before any service starts.
package custody_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

func TestKeyFileCustodyWithoutSecureBootOrTPM(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, nil, img, keys)
	opts := func(image string) harness.Options {
		return harness.Options{SecureBoot: harness.NoSecureBoot, Keys: keys, Disks: []harness.Disk{{Image: image}}}
	}

	first := harness.Boot(t, opts(img))
	first.Expect(`sneakers-init: phase=firstboot protection=reduced \(no Secure Boot firmware\)`, 5*time.Minute)
	first.Expect(`This box has no TPM`, time.Minute)
	first.Type("\r")
	first.Expect(`custody fixed \(key file\); state and backup formatted and mounted`, 3*time.Minute)
	first.Expect(`Protection: reduced \(no Secure Boot, no TPM\)`, time.Minute)
	first.Expect(`services: entering phase phase=firstboot`, time.Minute)
	first.Expect(`services: ready .*service=accessd`, time.Minute)
	first.Stable(90*time.Second, nil)
	first.Stop()

	next := harness.Boot(t, opts(first.Disk(0)))
	next.Expect(`state and backup unlocked and mounted \(key file, from the LUKS2 header\)`, 5*time.Minute)
	next.Expect(`services: ready .*service=accessd`, time.Minute)
	if strings.Contains(next.Console(), "This box has no TPM") {
		t.Fatal("the next boot asked for the custody again")
	}
	next.Stable(60*time.Second, nil)
	next.Stop()

	locked := next.Disk(0)
	wipeKeyfile(t, locked)
	vm := harness.Boot(t, opts(locked))
	vm.Expect(`State locked`, 5*time.Minute)
	vm.Expect(`KEYCUSTODY_LOCKED`, time.Minute)
	time.Sleep(15 * time.Second)
	if c := vm.Console(); strings.Contains(c, "services: entering phase") || strings.Contains(c, "This box has no TPM") {
		t.Fatal("a box whose state didn't unlock started services or ran first boot again")
	}
}

// wipeKeyfile zeroes the key at the start of the key-file partition, the
// first one first boot made.
func wipeKeyfile(t *testing.T, img string) {
	t.Helper()
	f, err := os.OpenFile(img, os.O_WRONLY, 0) // #nosec G304 -- the test's disk image
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(make([]byte, 32), disk.InstalledBytes("amd64")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

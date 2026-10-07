// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package harness_test

import (
	"os"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// TestHarnessBootsToSerialBanner boots the lab raw disk with Secure Boot
// enforcing and the lab keys enrolled, and waits for init's banner.
// SNEAKERS_IMAGE and SNEAKERS_KEYS come from build/lab/build.sh.
func TestHarnessBootsToSerialBanner(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, nil, img, keys)
	vm := harness.Boot(t, harness.Options{SecureBoot: harness.Enrolled, TPM: true, Keys: keys, Disks: []harness.Disk{{Image: img}}})
	vm.Expect(`sneakers-init: phase=firstboot`, 5*time.Minute)
}

// TestFirstBootStaysUp checks that once init has printed the phase, it
// keeps running and no service crash-loops: the banner alone came before
// init stopped on a read-only /run.
func TestFirstBootStaysUp(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, nil, img, keys)
	vm := harness.Boot(t, harness.Options{SecureBoot: harness.Enrolled, TPM: true, Keys: keys, Disks: []harness.Disk{{Image: img}}})
	vm.Expect(`sneakers-init: phase=firstboot`, 5*time.Minute)
	vm.Expect(`services: entering phase phase=firstboot`, time.Minute)
	vm.Stable(90*time.Second, map[string]string{
		"accessd": "init doesn't unlock and mount the state volume at /var/lib yet, so accessd can't create its state",
	})
}

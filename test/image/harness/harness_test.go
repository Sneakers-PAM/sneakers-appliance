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
// init stopped on a read-only /run. Enter at the protection step keeps the
// TPM.
func TestFirstBootStaysUp(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, nil, img, keys)
	vm := harness.Boot(t, harness.Options{SecureBoot: harness.Enrolled, TPM: true, Keys: keys, Disks: []harness.Disk{{Image: img}}})
	vm.Expect(`sneakers-init: phase=firstboot`, 5*time.Minute)
	vm.Expect(`Use the TPM \(recommended\)`, time.Minute)
	vm.Type("\r")
	vm.Expect(`custody fixed \(TPM\); state and backup formatted and mounted`, 3*time.Minute)
	vm.Expect(`Protection: full`, time.Minute)
	vm.Expect(`services: entering phase phase=firstboot`, time.Minute)
	vm.Expect(`services: ready .*service=accessd`, time.Minute)
	vm.Stable(90*time.Second, nil)
}

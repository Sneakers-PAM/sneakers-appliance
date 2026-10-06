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

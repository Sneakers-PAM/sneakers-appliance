// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package audittest_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit/audittest"
)

func TestIDShaped(t *testing.T) {
	for _, id := range []string{"0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", "a1b2c3d4e5f6", "R-7K2Q", "L-ABCD1234", "web-3F9K2Q", "ssh-1", "elevated-R-7K2Q", "SHA256:abc"} {
		if !audittest.IDShaped(id) {
			t.Errorf("%q isn't seen as an id", id)
		}
	}
	for _, name := range []string{"alice", "network", "box", "*.example.org", "alice's browser session from 192.0.2.20", "release 1.2.3", "admin", "product"} {
		if audittest.IDShaped(name) {
			t.Errorf("%q is seen as an id", name)
		}
	}
}

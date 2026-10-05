// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package fixtures_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func TestFixtureArtifactIsComplete(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{Arch: "amd64"})
	for _, f := range []string{"index.json", "oci-layout"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if pins.Channel != "lab" {
		t.Fatal("fixture pins must be lab")
	}
}

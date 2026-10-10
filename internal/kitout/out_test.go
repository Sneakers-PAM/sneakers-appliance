// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package kitout_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// Every image a kit writes is named sneakers-appliance-<v>-<arch>: the
// version on production, lab-<build label> on lab, with the format as the
// extension. No build date, time or commit.
func TestTheImageBaseName(t *testing.T) {
	for _, c := range []struct{ version, channel, arch, want string }{
		{"0.1.0-rc.1", release.ChannelProduction, "amd64", "sneakers-appliance-0.1.0-rc.1-amd64"},
		{"0.1.0", release.ChannelProduction, "arm64", "sneakers-appliance-0.1.0-arm64"},
		{"0.0.0-lab.20261010n3.r20261010105645-ga8df881", release.ChannelLab, "amd64", "sneakers-appliance-lab-n3-amd64"},
	} {
		s := &verify.State{Manifest: &verify.Manifest{Metadata: verify.Metadata{Version: c.version, Channel: c.channel}, Spec: verify.Spec{Arch: c.arch}}}
		if got := kitout.BaseName(s); got != c.want {
			t.Errorf("BaseName(%s %s) = %s, want %s", c.version, c.channel, got, c.want)
		}
	}
}

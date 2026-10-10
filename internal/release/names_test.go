// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package release_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// A file name carries the version alone on production and the build's
// label on lab: never the build date, the build time or the commit, which
// stay in the signed header and the index.
func TestTheNameVersion(t *testing.T) {
	for _, c := range []struct{ version, channel, want string }{
		{"0.1.0-rc.1", release.ChannelProduction, "0.1.0-rc.1"},
		{"0.1.0", release.ChannelProduction, "0.1.0"},
		{"0.0.0-lab.20261010n3.r20261010105645-ga8df881", release.ChannelLab, "lab-n3"},
		{"0.0.0-lab.20261010n.r20261010105645-ga8df881", release.ChannelLab, "lab-n"},
		{"0.0.0-lab.20261012m-g1a2b3c4", release.ChannelLab, "lab-m"},
		{"0.0.0-lab.20261012m1-g1a2b3c4", release.ChannelLab, "lab-m1"},
		{"0.0.0-lab.20261010n5w1.r20261010163323-g433866c", release.ChannelLab, "lab-n5w1"},
		{"0.1.0-lab.sneakers.10", release.ChannelLab, "lab-sneakers.10"},
		{"0.0.0-lab.1-g1a2b3c4", release.ChannelLab, "lab-1"},
		{"0.2.0", release.ChannelLab, "lab-0.2.0"},
		{"0.3.2-g1a2b3c4", release.ChannelLab, "lab-0.3.2"},
		{"0.1.0-rc.1", release.ChannelLab, "lab-0.1.0-rc.1"},
	} {
		if got := release.NameVersion(c.version, c.channel); got != c.want {
			t.Errorf("NameVersion(%q, %s) = %q, want %q", c.version, c.channel, got, c.want)
		}
	}
}

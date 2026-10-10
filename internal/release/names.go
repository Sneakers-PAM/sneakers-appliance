// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"regexp"
	"strings"
)

var (
	datedBuildRE = regexp.MustCompile(`(?:^|\.)[0-9]{8}([a-z][0-9]*(?:w[0-9]+)?)(?:$|[.-])`)
	buildTimeRE  = regexp.MustCompile(`\.r[0-9]{14}`)
	commitTailRE = regexp.MustCompile(`-g[0-9a-f]{7,40}$`)
)

// NameVersion is the part of a file name that stands for a release: the
// version on production (0.1.0-rc.1), and lab-<label> on lab, where the
// label is the build's letter and rebuild number (lab-n3), with w<n> for
// a Base Web-only hotfix on that build (lab-n5w1), or the
// product's own lab label (lab-sneakers.10). The build date, the build
// time and the commit never go in a name; the signed header and the index
// carry the full version.
func NameVersion(version, channel string) string {
	if channel != ChannelLab {
		return version
	}
	return "lab-" + labLabel(version)
}

func labLabel(version string) string {
	v := commitTailRE.ReplaceAllString(buildTimeRE.ReplaceAllString(version, ""), "")
	core, rest, ok := strings.Cut(v, "-")
	if !ok {
		return core
	}
	if m := datedBuildRE.FindStringSubmatch(rest); m != nil {
		return m[1]
	}
	if label, ok := strings.CutPrefix(rest, "lab."); ok && label != "" {
		return label
	}
	if rest == "" {
		return core
	}
	return core + "-" + rest
}

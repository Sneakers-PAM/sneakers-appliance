// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

// Resources is the product's database cluster the box renders itself, from a
// chart the bundle carries (docs/resources.md), so an admin's settings apply
// at install, update and revert without a rebuilt bundle.
type Resources struct {
	// Chart names the release.yaml spec.thirdParty entry whose chart the
	// bundle carries in charts/. The release pins the chart's name, version
	// and registry digest; the bundle check holds the archive to that pin.
	Chart string `yaml:"chart"`
}

func (s Spec) checkResources() error {
	if s.Resources == nil {
		return nil
	}
	if !nameRE.MatchString(s.Resources.Chart) {
		return bad("resources.chart: %q isn't the name of a release.yaml third-party entry", s.Resources.Chart)
	}
	return nil
}

// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"path"
	"regexp"
	"slices"
)

// Resources is the product's database cluster the box renders itself, from a
// chart the bundle carries (docs/resources.md), so an admin's settings apply
// at install, update and revert without a rebuilt bundle.
type Resources struct {
	// Chart names the release.yaml spec.thirdParty entry whose chart the
	// bundle carries in charts/. The release pins the chart's name, version
	// and registry digest; the bundle check holds the archive to that pin.
	Chart string `yaml:"chart"`
	// Phase is the product.yaml phase whose stack holds the cluster: every
	// workload the chart renders must be one of that phase's workloads.
	Phase string `yaml:"phase"`
	// Release is the helm release name the box renders with. It names the
	// objects and their selector labels, so it must be the name the cluster
	// already runs under.
	Release string `yaml:"release"`
	// Namespace is the product's namespace, which another stack creates.
	Namespace string `yaml:"namespace"`
	// Data is the directory the volumes' hostPaths go under.
	Data string `yaml:"data"`
	// WaitJob names the release's Job image (spec.jobs) whose wait command
	// each workload's init container runs; empty adds none.
	WaitJob string `yaml:"wait_job"`
	// Values are the chart's values the product sets, as they would be in
	// a values file.
	Values map[string]any `yaml:"values"`
}

var (
	resourcesReleaseRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,52}$`)
	resourcesNamespaceRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func (s Spec) checkResources() error {
	if s.Resources == nil {
		return nil
	}
	if !nameRE.MatchString(s.Resources.Chart) {
		return bad("resources.chart: %q isn't the name of a release.yaml third-party entry", s.Resources.Chart)
	}
	r := s.Resources
	if !slices.ContainsFunc(s.Phases, func(p Phase) bool { return p.Name == r.Phase }) {
		return bad("resources.phase: %q isn't a phase of product.yaml", r.Phase)
	}
	if !resourcesReleaseRE.MatchString(r.Release) {
		return bad("resources.release: %q isn't a helm release name", r.Release)
	}
	if !resourcesNamespaceRE.MatchString(r.Namespace) {
		return bad("resources.namespace: %q isn't a namespace name", r.Namespace)
	}
	if !path.IsAbs(r.Data) || path.Clean(r.Data) != r.Data || r.Data == "/" {
		return bad("resources.data: %q isn't a clean absolute directory", r.Data)
	}
	if r.WaitJob != "" && !nameRE.MatchString(r.WaitJob) {
		return bad("resources.wait_job: %q isn't the name of a release.yaml job", r.WaitJob)
	}
	return nil
}

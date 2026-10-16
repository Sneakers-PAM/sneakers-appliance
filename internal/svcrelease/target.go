// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package svcrelease is the appliance release's service repo checklist
// (docs/release.md#the-service-repo-checklist): for every repository a
// release pins, whether its tagged commit already has a published
// release, or whether its draft needs publishing and, if so, with what
// target and notes. It reads GitHub read-only; nothing here writes to a
// service repo.
package svcrelease

import (
	"sort"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
)

// Target is one repository a release pins: Name is the short label the
// checklist shows (a release.yaml service key, or "release"/"web"),
// Repo is "<owner>/<name>", Commit the full pinned SHA.
type Target struct {
	Name, Repo, Commit string
}

// Targets is every repository rel pins, plus sneakers-release and
// sneakers-web (which release.yaml doesn't name itself), de-duplicated by
// repository and sorted by name. A service with no build block (an image
// the release only pulls, never builds) is skipped.
func Targets(rel *bundle.Release, releaseRepo, releaseCommit, webRepo, webCommit string) []Target {
	seen := map[string]bool{}
	var out []Target
	add := func(name, repo, commit string) {
		if repo == "" || commit == "" || seen[repo] {
			return
		}
		seen[repo] = true
		out = append(out, Target{Name: name, Repo: repo, Commit: commit})
	}
	for name, img := range rel.Spec.Services {
		if img.Build != nil {
			add(name, img.Build.Repository, img.Build.Commit)
		}
	}
	add("release", releaseRepo, releaseCommit)
	add("web", webRepo, webCommit)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package svcrelease_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/svcrelease"
)

// Targets lists every service release.yaml builds, plus sneakers-release
// and sneakers-web (which it doesn't name itself), sorted and
// de-duplicated; a pulled (not built) image is skipped.
func TestTargetsFromReleaseYAML(t *testing.T) {
	rel, err := bundle.ParseRelease([]byte(`
apiVersion: sneakers-pam/v1alpha1
kind: Release
spec:
  services:
    vault:
      image: ghcr.io/sneakers-pam/sneakers-vault
      digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      build:
        repository: Sneakers-PAM/sneakers-vault
        commit: 1111111111111111111111111111111111111b
    identity:
      image: ghcr.io/sneakers-pam/sneakers-identity
      digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      build:
        repository: Sneakers-PAM/sneakers-identity
        commit: 2222222222222222222222222222222222222c
    migrate:
      image: ghcr.io/sneakers-pam/sneakers-migrate
      digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
thirdParty:
  postgres:
    image: docker.io/library/postgres
    digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
`))
	if err != nil {
		t.Fatal(err)
	}
	got := svcrelease.Targets(rel, "Sneakers-PAM/sneakers-release", "3333333333333333333333333333333333333d", "Sneakers-PAM/sneakers-web", "4444444444444444444444444444444444444e")
	want := []svcrelease.Target{
		{Name: "identity", Repo: "Sneakers-PAM/sneakers-identity", Commit: "2222222222222222222222222222222222222c"},
		{Name: "release", Repo: "Sneakers-PAM/sneakers-release", Commit: "3333333333333333333333333333333333333d"},
		{Name: "vault", Repo: "Sneakers-PAM/sneakers-vault", Commit: "1111111111111111111111111111111111111b"},
		{Name: "web", Repo: "Sneakers-PAM/sneakers-web", Commit: "4444444444444444444444444444444444444e"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

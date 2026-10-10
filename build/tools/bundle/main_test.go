// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pinned = `apiVersion: sneakers-pam/v1alpha1
kind: Release
spec:
  services:
    vault:
      image: ghcr.io/sneakers-pam/sneakers-vault
      digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  thirdParty:
    postgres:
      image: docker.io/library/postgres
      digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  tools:
    curl:
      image: docker.io/curlimages/curl
      digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  kubernetes:
    k0s:
      images:
        - image: quay.io/k0sproject/pause
          digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
`

func writeRelease(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "release.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImagesListsEveryBundledImageSorted(t *testing.T) {
	var out bytes.Buffer
	if err := images([]string{"--release", writeRelease(t, pinned)}, &out); err != nil {
		t.Fatal(err)
	}
	want := "docker.io/library/postgres sha256:" + strings.Repeat("a", 64) + "\n" +
		"ghcr.io/sneakers-pam/sneakers-vault sha256:" + strings.Repeat("b", 64) + "\n" +
		"quay.io/k0sproject/pause sha256:" + strings.Repeat("d", 64) + "\n"
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
}

func TestImagesRefusesAPlaceholderDigest(t *testing.T) {
	body := strings.Replace(pinned, "sha256:"+strings.Repeat("b", 64), "sha256:TBD-at-release", 1)
	var out bytes.Buffer
	err := images([]string{"--release", writeRelease(t, body)}, &out)
	if err == nil || !strings.Contains(err.Error(), "services.vault") {
		t.Fatalf("want a refusal naming services.vault, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("wrote %q before refusing", out.String())
	}
}

const withBuilds = `apiVersion: sneakers-pam/v1alpha1
kind: Release
spec:
  services:
    web-staff:
      image: ghcr.io/sneakers-pam/sneakers-web-staff
      version: 0.1.0
      digest: sha256:TBD-at-release
      build:
        repository: Sneakers-PAM/sneakers-web
        commit: 9c24045aaa1d4a1288176934d9ee9557aa250b32
        dockerfile: Dockerfile
        context: .
        args:
          APP: staff
          EDGE: live
    vault:
      image: ghcr.io/sneakers-pam/sneakers-vault
      version: 0.1.0
      digest: sha256:TBD-at-release
      build:
        repository: Sneakers-PAM/sneakers-vault
        commit: 2644629a50c138764f89d897bcc4b2e6c78e2924
        dockerfile: Dockerfile
        context: .
        target: vault
  jobs:
    migrate:
      image: ghcr.io/sneakers-pam/sneakers-migrate
      version: 0.1.0
      digest: sha256:TBD-at-release
      build:
        repository: Sneakers-PAM/sneakers-release
        commit: 59056d56b316b32d768bebd608399d0a97b269ee
        dockerfile: migrate/Dockerfile
        context: .
  thirdParty:
    postgres:
      image: docker.io/library/postgres
      digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`

// sources lists every service image the release builds, one line each,
// for build/release/images.sh.
func TestSourcesListsEveryServiceBuild(t *testing.T) {
	var out bytes.Buffer
	if err := sources([]string{"--release", writeRelease(t, withBuilds)}, &out); err != nil {
		t.Fatal(err)
	}
	want := "migrate ghcr.io/sneakers-pam/sneakers-migrate 0.1.0 Sneakers-PAM/sneakers-release 59056d56b316b32d768bebd608399d0a97b269ee migrate/Dockerfile . - -\n" +
		"vault ghcr.io/sneakers-pam/sneakers-vault 0.1.0 Sneakers-PAM/sneakers-vault 2644629a50c138764f89d897bcc4b2e6c78e2924 Dockerfile . vault -\n" +
		"web-staff ghcr.io/sneakers-pam/sneakers-web-staff 0.1.0 Sneakers-PAM/sneakers-web 9c24045aaa1d4a1288176934d9ee9557aa250b32 Dockerfile . - APP=staff,EDGE=live\n"
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
}

func TestSourcesRefusesAServiceWithoutABuild(t *testing.T) {
	for name, body := range map[string]string{
		"no build":       strings.Replace(withBuilds, "      build:\n        repository: Sneakers-PAM/sneakers-vault\n        commit: 2644629a50c138764f89d897bcc4b2e6c78e2924\n        dockerfile: Dockerfile\n        context: .\n        target: vault\n", "", 1),
		"a short commit": strings.Replace(withBuilds, "2644629a50c138764f89d897bcc4b2e6c78e2924", "2644629", 1),
		"a path outside": strings.Replace(withBuilds, "dockerfile: Dockerfile\n        context: .\n        target", "dockerfile: ../Dockerfile\n        context: .\n        target", 1),
		"a spaced arg":   strings.Replace(withBuilds, "EDGE: live", "EDGE: live mock", 1),
		"no version":     strings.Replace(withBuilds, "      version: 0.1.0\n", "", 1),
		"another repo":   strings.Replace(withBuilds, "repository: Sneakers-PAM/sneakers-vault", "repository: example/sneakers-vault x", 1),
		"no image":       strings.Replace(withBuilds, "      image: ghcr.io/sneakers-pam/sneakers-vault\n", "", 1),
	} {
		var out bytes.Buffer
		if err := sources([]string{"--release", writeRelease(t, body)}, &out); err == nil {
			t.Errorf("%s: listed\n%s", name, out.String())
		}
	}
}

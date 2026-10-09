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

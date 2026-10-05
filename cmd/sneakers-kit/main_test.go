// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

func TestUnpinnedKitRefusesToStart(t *testing.T) {
	restore := release.SetForTest("", "", "", "", "")
	defer restore()
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code == 0 {
		t.Fatal("an unpinned kit must exit non-zero")
	}
	if !strings.Contains(errOut.String(), "KIT_PIN_MISSING") {
		t.Fatalf("stderr %q", errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestVersionPrintsChannelAndFingerprints(t *testing.T) {
	db := testpki.SelfSigned(t, "db")
	restore := release.SetForTest("lab", string(testpki.ECDSA(t).PublicPEM), string(db.PEM),
		string(testpki.SelfSigned(t, "PK").PEM), string(testpki.SelfSigned(t, "KEK").PEM))
	defer restore()
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	p, _ := release.Load()
	for _, want := range []string{"channel: lab", "version: " + release.Version, "db: " + p.Fingerprints().DB, "release key: ", "PK: ", "KEK: "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %q", want, out.String())
		}
	}
}

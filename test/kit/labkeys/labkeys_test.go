// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build tools

// Package labkeys runs build/keys/lab-keys.sh with the real tools and checks
// that what cosign writes verifies with the kit's own verifier. CI runs it in
// the lab tools job (`go test -tags tools ./test/kit/labkeys/`).
package labkeys

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
)

func labKeys(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "keys")
	script, err := filepath.Abs("../../../build/keys/lab-keys.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, out) // #nosec G204 -- the repo's own script
	cmd.Dir = t.TempDir()
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lab-keys.sh: %v\n%s", err, b)
	}
	if left, _ := os.ReadDir(cmd.Dir); len(left) != 0 {
		t.Fatalf("lab-keys.sh wrote outside its output directory: %v", left)
	}
	return out
}

func TestLabKeysWritesTheWholeSet(t *testing.T) {
	out := labKeys(t)
	for _, f := range []string{
		"PK.key", "PK.crt", "KEK.key", "KEK.crt", "db.key", "db.crt", "rogue-db.key", "rogue-db.crt",
		"PK.esl", "KEK.esl", "db.esl", "dbx.esl", "PK.auth", "KEK.auth", "db.auth", "dbx.auth",
		"cosign.key", "cosign.pub", "rogue-cosign.key", "rogue-cosign.pub",
	} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Error(err)
		}
	}
	for _, role := range []string{"PK", "KEK", "db", "rogue-db"} {
		b, err := os.ReadFile(filepath.Join(out, role+".crt"))
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(b)
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if want := "Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION " + role; c.Subject.CommonName != want {
			t.Errorf("%s subject %q", role, c.Subject.CommonName)
		}
	}
}

func TestCosignBlobBundleVerifies(t *testing.T) {
	out := labKeys(t)
	blob := filepath.Join(t.TempDir(), "release.yaml")
	if err := os.WriteFile(blob, []byte("apiVersion: sneakers-pam/v1alpha1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundlePath := blob + ".sigstore.json"
	cmd := exec.Command("cosign", "sign-blob", "--yes", "--key", filepath.Join(out, "cosign.key"),
		"--bundle", bundlePath, "--tlog-upload=false", "--use-signing-config=false", blob)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cosign sign-blob: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := sigbundle.Parse(raw)
	if err != nil {
		t.Fatalf("parse cosign's bundle: %v\n%s", err, raw)
	}
	data, _ := os.ReadFile(blob)
	for name, wantOK := range map[string]bool{"cosign.pub": true, "rogue-cosign.pub": false} {
		pubPEM, _ := os.ReadFile(filepath.Join(out, name))
		pub, err := sigbundle.ParsePublicKey(pubPEM)
		if err != nil {
			t.Fatal(err)
		}
		if err := bd.Verify(pub, sha256.Sum256(data)); (err == nil) != wantOK {
			t.Errorf("%s: %v", name, err)
		}
	}
	if strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("a bundle never carries key material")
	}
}

// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build tools

// Package labkeys runs build/keys/lab-keys.sh with the real tools and checks
// that what cosign writes verifies with the kit's own verifier. CI runs it in
// the lab tools job (`go test -tags tools ./test/kit/labkeys/`).
package labkeys

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/foxboron/go-uefi/authenticode"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ukipcr"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
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
		"update.key", "update.pub", "rogue-update.key", "rogue-update.pub",
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

func TestEfitoolsAuthFilesVerify(t *testing.T) {
	out := labKeys(t)
	cert := func(role string) *x509.Certificate {
		b, err := os.ReadFile(filepath.Join(out, role+".crt"))
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(b)
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, c := range []struct{ name, signer, rogue string }{
		{"PK", "PK", "KEK"}, {"KEK", "PK", "KEK"}, {"db", "KEK", "PK"}, {"dbx", "KEK", "rogue-db"},
	} {
		raw, err := os.ReadFile(filepath.Join(out, c.name+".auth"))
		if err != nil {
			t.Fatal(err)
		}
		a, err := efiauth.ParseAuth(raw)
		if err != nil {
			t.Fatalf("%s.auth: %v", c.name, err)
		}
		esl, _ := os.ReadFile(filepath.Join(out, c.name+".esl"))
		if !bytes.Equal(a.Data, esl) {
			t.Errorf("%s.auth doesn't carry %s.esl", c.name, c.name)
		}
		if err := a.Verify(c.name, cert(c.signer)); err != nil {
			t.Errorf("%s.auth with %s: %v", c.name, c.signer, err)
		}
		if err := a.Verify(c.name, cert(c.rogue)); err == nil {
			t.Errorf("%s.auth verified with %s", c.name, c.rogue)
		}
	}
	for _, role := range []string{"PK", "KEK", "db"} {
		esl, _ := os.ReadFile(filepath.Join(out, role+".esl"))
		entries, err := efiauth.ParseSignatureLists(esl)
		if err != nil || len(entries) != 1 || !bytes.Equal(entries[0].Data, cert(role).Raw) {
			t.Errorf("%s.esl: %d entries, %v", role, len(entries), err)
		}
	}
}

func TestSbsignSignatureVerifiesWithTheKitsCheck(t *testing.T) {
	out := labKeys(t)
	dir := t.TempDir()
	unsigned := filepath.Join(dir, "uki.efi")
	if err := os.WriteFile(unsigned, fixtures.PE(t, fixtures.Section{Name: ".cmdline", Data: []byte("quiet")}, fixtures.Section{Name: ".linux", Data: []byte("kernel")}), 0o600); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(dir, "uki.signed.efi")
	cmd := exec.Command("sbsign", "--key", filepath.Join(out, "db.key"), "--cert", filepath.Join(out, "db.crt"), "--output", signed, unsigned)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sbsign: %v\n%s", err, b)
	}
	f, err := os.Open(signed) // #nosec G304 -- the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	p, err := authenticode.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	read := func(role string) *x509.Certificate {
		b, _ := os.ReadFile(filepath.Join(out, role+".crt"))
		blk, _ := pem.Decode(b)
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if ok, err := p.Verify(read("db")); err != nil || !ok {
		t.Fatalf("sbsign's signature doesn't verify: %v", err)
	}
	if ok, _ := p.Verify(read("rogue-db")); ok {
		t.Fatal("verified with the rogue db")
	}
}

func TestFixtureSignatureVerifiesWithSbverify(t *testing.T) {
	k := fixtures.LabKeys(t)
	dir := t.TempDir()
	uki := filepath.Join(dir, "uki.efi")
	if err := os.WriteFile(uki, fixtures.UKI(t, k.DB, "quiet"), 0o600); err != nil {
		t.Fatal(err)
	}
	crt := filepath.Join(dir, "db.crt")
	if err := os.WriteFile(crt, k.DB.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("sbverify", "--cert", crt, uki).CombinedOutput(); err != nil { // #nosec G204 -- test-only, fixed tool
		t.Fatalf("sbverify: %v\n%s", err, b)
	}
}

func TestFixtureSquashFSReadsWithUnsquashfs(t *testing.T) {
	tree, _ := fixtures.RootTree(t, fixtures.LabKeys(t), "amd64", nil)
	img := filepath.Join(t.TempDir(), "root.sqfs")
	if err := os.WriteFile(img, fixtures.SquashFS(t, tree), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := exec.Command("unsquashfs", "-l", img).CombinedOutput() // #nosec G204 -- test-only, fixed tool
	if err != nil {
		t.Fatalf("unsquashfs: %v\n%s", err, b)
	}
	if !strings.Contains(string(b), "usr/share/sneakers/release/release.yaml") {
		t.Fatalf("listing:\n%s", b)
	}
}

// TestAssembleUKI builds a UKI with the real ukify, checks it carries
// exactly the six sections and the signed command line, and that sbsign's
// signature on it verifies with the kit's Authenticode check.
func TestAssembleUKI(t *testing.T) {
	out := labKeys(t)
	dir := t.TempDir()
	kernel := filepath.Join(dir, "bzImage")
	if err := os.WriteFile(kernel, bytes.Repeat([]byte{0x90}, 64<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	vj := filepath.Join(dir, "verity.json")
	root := strings.Repeat("cd", 32)
	if err := os.WriteFile(vj, []byte(`{"roothash":"`+root+`","hashOffset":8192}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vs, err := exec.LookPath("veritysetup")
	if err != nil {
		t.Fatal(err)
	}
	script, _ := filepath.Abs("../../../build/uki/assemble.sh")
	cmd := exec.Command("bash", script) // #nosec G204 -- the repo's own script
	cmd.Env = append(os.Environ(), "KERNEL="+kernel, "VERITYSETUP="+vs, "VERITY_JSON="+vj, "VERSION=0.1.0",
		"OUT="+filepath.Join(dir, "out"), "UNAME=6.12.0-sneakers", "SOURCE_DATE_EPOCH=1700000000")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("assemble.sh: %v\n%s", err, b)
	}
	uki := filepath.Join(dir, "out", "sneakers-0.1.0.efi")
	b, err := os.ReadFile(uki) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	p, err := ukipcr.Predict(b)
	if err != nil || strings.Join(p.Sections, " ") != ".linux .osrel .cmdline .initrd .uname .sbat" {
		t.Fatalf("sections %v %v", p.Sections, err)
	}
	signed := uki + ".signed"
	if b, err := exec.Command("sbsign", "--key", filepath.Join(out, "db.key"), "--cert", filepath.Join(out, "db.crt"), "--output", signed, uki).CombinedOutput(); err != nil { // #nosec G204 -- test-only, fixed tool
		t.Fatalf("sbsign: %v\n%s", err, b)
	}
	f, err := os.Open(signed) // #nosec G304 -- as above
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	pe, err := authenticode.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := os.ReadFile(filepath.Join(out, "db.crt"))
	blk, _ := pem.Decode(crt)
	c, _ := x509.ParseCertificate(blk.Bytes)
	if ok, err := pe.Verify(c); err != nil || !ok {
		t.Fatalf("the signed UKI doesn't verify: %v", err)
	}
	pf, err := os.ReadFile(signed) // #nosec G304 -- as above
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pf, []byte("sneakers.roothash="+root+" sneakers.hashoffset=8192 sneakers.version=0.1.0 quiet loglevel=1 console=tty0 console=ttyS0 fbcon=font:TER16x32 panic=10 lockdown=integrity")) {
		t.Fatal("the command line isn't the spec's")
	}
}

// TestCosignSignedUpdatePackageVerifies makes a lab .bin the way the release
// workflow does, with the real cosign over the header, and reads it back with
// the box's own reader: the lab keys verify and decrypt it, the rogue ones
// don't.
func TestCosignSignedUpdatePackageVerifies(t *testing.T) {
	out := labKeys(t)
	for _, f := range []string{"update.key", "update.pub"} {
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil || !strings.Contains(string(b), "LAB ephemeral NOT FOR PRODUCTION") {
			t.Fatalf("%s isn't labelled lab: %v", f, err)
		}
	}
	recipient := func(name string) *age.X25519Recipient {
		b, _ := os.ReadFile(filepath.Join(out, name))
		rs, err := age.ParseRecipients(bytes.NewReader(b))
		if err != nil || len(rs) != 1 {
			t.Fatalf("%s: %v", name, err)
		}
		return rs[0].(*age.X25519Recipient)
	}
	identity := func(name string) age.Identity {
		b, _ := os.ReadFile(filepath.Join(out, name))
		ids, err := age.ParseIdentities(bytes.NewReader(b))
		if err != nil || len(ids) != 1 {
			t.Fatalf("%s: %v", name, err)
		}
		return ids[0]
	}
	payload := []byte("a signed artifact layout")
	var ct bytes.Buffer
	h, err := updatepkg.Encrypt(bytes.NewReader(payload), updatepkg.Header{Version: "0.0.1", Arch: "amd64", Kind: updatepkg.KindFull, Channel: "lab"}, recipient("update.pub"), &ct)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := h.Marshal()
	hdrPath := filepath.Join(t.TempDir(), "header.json")
	if err := os.WriteFile(hdrPath, hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cosign", "sign-blob", "--yes", "--key", filepath.Join(out, "cosign.key"),
		"--bundle", hdrPath+".sigstore.json", "--tlog-upload=false", "--use-signing-config=false", hdrPath)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cosign sign-blob: %v\n%s", err, b)
	}
	bundle, _ := os.ReadFile(hdrPath + ".sigstore.json")
	var bin bytes.Buffer
	if err := updatepkg.Seal(&bin, hdr, bundle, &ct); err != nil {
		t.Fatal(err)
	}
	read := func() *updatepkg.Package {
		p, err := updatepkg.Read(bytes.NewReader(bin.Bytes()), int64(bin.Len()))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	rogue, _ := os.ReadFile(filepath.Join(out, "rogue-cosign.pub"))
	if err := read().Verify(rogue, "lab"); err == nil {
		t.Fatal("the rogue release key verified the package")
	}
	pub, _ := os.ReadFile(filepath.Join(out, "cosign.pub"))
	p := read()
	if err := p.Verify(pub, "lab"); err != nil {
		t.Fatal(err)
	}
	if err := p.Decrypt(identity("rogue-update.key"), &bytes.Buffer{}); err == nil {
		t.Fatal("the rogue update key decrypted the package")
	}
	var got bytes.Buffer
	if err := p.Decrypt(identity("update.key"), &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("decrypt: %q, %v", got.String(), err)
	}
}

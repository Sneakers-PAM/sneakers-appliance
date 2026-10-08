// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/fstest"

	"github.com/foxboron/go-uefi/authenticode"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// Owner is the signature-owner GUID of the fixture's signature lists.
var Owner = [16]byte{0x5d, 0x4c, 0x8e, 0x4b, 0x3b, 0x9b, 0x4b, 0x58, 0x9e, 0x2c, 0x0d, 0x7e, 0x1f, 0x2a, 0x3b, 0x4c}

// Cmdline is the UKI command line of spec 1 Section 3.3.
func Cmdline(rootHash string, hashOffset int64) string {
	return fmt.Sprintf("sneakers.roothash=%s sneakers.hashoffset=%d sneakers.version=%s quiet console=tty0 console=ttyS0 fbcon=font:TER16x32 panic=10 lockdown=integrity",
		rootHash, hashOffset, Version)
}

// UKI is a stub UKI with the six sections and the given command line,
// signed with signer.
func UKI(t testing.TB, signer testpki.Cert, cmdline string) []byte {
	t.Helper()
	return Sign(t, signer, PE(t,
		Section{".osrel", []byte("ID=sneakers\nVERSION_ID=" + Version + "\n")},
		Section{".cmdline", []byte(cmdline)},
		Section{".uname", []byte("6.12.0-sneakers")},
		Section{".sbat", []byte("sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\nsneakers-pam,1,Sneakers-PAM,sneakers,1\n")},
		Section{".linux", random(t, 8<<10)},
		Section{".initrd", random(t, 8<<10)},
	))
}

// Sign adds an Authenticode signature by signer to a PE image.
func Sign(t testing.TB, signer testpki.Cert, img []byte) []byte {
	t.Helper()
	p, err := authenticode.Parse(bytes.NewReader(img))
	must(t, err)
	_, err = p.Sign(signer.Key, signer.Cert)
	must(t, err)
	return p.Bytes()
}

// baseParts builds every release file of a valid fixture.
func baseParts(t testing.TB, k Keys, arch string, rootEdit func(fstest.MapFS)) *Parts {
	t.Helper()
	tree, rel := RootTree(t, k, arch, rootEdit)
	img, rootHash, offset := RootImage(t, tree)
	p := &Parts{Keys: k, Arch: arch, RootHash: rootHash, HashOffset: offset, Files: map[string][]byte{
		verify.FileRelease:    rel,
		verify.FileReleaseSig: k.Cosign.BlobBundle(t, rel),
		rootName():            img,
	}}
	if arch == "amd64" {
		p.Files[ukiName()] = UKI(t, k.DB, Cmdline(rootHash, offset))
		p.Files["systemd-bootx64.efi"] = Sign(t, k.DB, PE(t, Section{".text", random(t, 4<<10)}))
		pk, kek, db := efiauth.X509List(Owner, k.PK.Cert.Raw), efiauth.X509List(Owner, k.KEK.Cert.Raw), efiauth.X509List(Owner, k.DB.Cert.Raw)
		p.Files["keys/PK.esl"], p.Files["keys/KEK.esl"], p.Files["keys/db.esl"], p.Files["keys/dbx.esl"] = pk, kek, db, []byte{}
		p.Files["keys/PK.auth"] = k.PK.AuthFile(t, "PK", pk)
		p.Files["keys/KEK.auth"] = k.PK.AuthFile(t, "KEK", kek)
		p.Files["keys/db.auth"] = k.KEK.AuthFile(t, "db", db)
	} else {
		p.Files[arm64Name()] = BootTarball(t, map[string][]byte{
			"Image":               random(t, 8<<10),
			"initrd.img":          random(t, 4<<10),
			"bcm2711-rpi-4-b.dtb": random(t, 1<<10),
			"config.txt":          []byte("arm_64bit=1\nkernel=Image\ninitramfs initrd.img followkernel\n"),
			"cmdline.txt":         []byte(Cmdline(rootHash, offset) + " cgroup_enable=memory\n"),
		})
	}
	return p
}

// BootTarball packs the arm64 boot files.
func BootTarball(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range sortedNames(files) {
		must(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name])), Typeflag: tar.TypeReg}))
		_, err := tw.Write(files[name])
		must(t, err)
	}
	must(t, tw.Close())
	return buf.Bytes()
}

func tarDigests(b []byte) map[string]string {
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) || err != nil {
			return out
		}
		s := sha256.New()
		_, _ = io.CopyN(s, tr, 1<<20)
		out[h.Name] = hex.EncodeToString(s.Sum(nil))
	}
}

// The mutations of steps 6 to 9.

// ResignUKIWithRogueDB signs the UKI with a db key that isn't pinned.
var ResignUKIWithRogueDB = Mutation{Files: func(p *Parts) {
	p.Files[ukiName()] = UKI(&noFail{}, p.Keys.RogueDB, Cmdline(p.RootHash, p.HashOffset))
}}

// ResignLoaderWithRogueDB signs systemd-boot with a db key that isn't pinned.
var ResignLoaderWithRogueDB = Mutation{Files: func(p *Parts) {
	p.Files["systemd-bootx64.efi"] = Sign(&noFail{}, p.Keys.RogueDB, PE(&noFail{}, Section{".text", []byte("rogue loader")}))
}}

// UnsignedUKI ships a UKI with no signature at all.
var UnsignedUKI = Mutation{Files: func(p *Parts) {
	p.Files[ukiName()] = PE(&noFail{}, Section{".cmdline", []byte(Cmdline(p.RootHash, p.HashOffset))})
}}

// AppendCertToDBESL adds a second certificate to db, re-signed by KEK so
// only the list check can catch it.
var AppendCertToDBESL = Mutation{Files: func(p *Parts) {
	db := append(efiauth.X509List(Owner, p.Keys.DB.Cert.Raw), efiauth.X509List(Owner, p.Keys.RogueDB.Cert.Raw)...)
	p.Files["keys/db.esl"] = db
	p.Files["keys/db.auth"] = p.Keys.KEK.AuthFile(&noFail{}, "db", db)
}}

// DBAuthSignedByPK signs db.auth with PK instead of KEK.
var DBAuthSignedByPK = Mutation{Files: func(p *Parts) {
	p.Files["keys/db.auth"] = p.Keys.PK.AuthFile(&noFail{}, "db", p.Files["keys/db.esl"])
}}

// FlipRootByte flips one byte of the root's data area before the digests
// are written, so only the verity check can catch it.
var FlipRootByte = Mutation{Files: func(p *Parts) {
	p.Files[rootName()][100] ^= 0x01
}}

// CmdlineOtherRootHash builds the UKI with a root hash that isn't the
// manifest's.
var CmdlineOtherRootHash = Mutation{Files: func(p *Parts) {
	other := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	if p.Arch == "arm64" {
		return
	}
	p.Files[ukiName()] = UKI(&noFail{}, p.Keys.DB, Cmdline(other, p.HashOffset))
}}

// Arm64ExtraBootFile adds a file to the boot tarball that appliance.yaml
// won't list.
var Arm64ExtraBootFile = Mutation{Manifest: func(m *verify.Manifest) {
	delete(m.Spec.Boot.Arm64.Files, "config.txt")
}}

// Arm64CmdlineOtherRootHash puts another root hash in cmdline.txt.
var Arm64CmdlineOtherRootHash = Mutation{Files: func(p *Parts) {
	other := hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	p.Files[arm64Name()] = BootTarball(&noFail{}, map[string][]byte{
		"Image":       []byte("kernel"),
		"cmdline.txt": []byte(Cmdline(other, p.HashOffset)),
	})
}}

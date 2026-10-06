// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package ova_test

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ova"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func TestOVFRendersAndValidates(t *testing.T) {
	ovf := ova.Render(ova.Params{Version: "0.1.0", DiskBytes: 64 << 30, AuthBypass: true})
	for _, want := range []string{`vmx-19`, `vmw:key="firmware" vmw:value="efi"`, `uefi.allowAuthBypass" vmw:value="TRUE`, `uefi.secureBoot.enabled" vmw:value="FALSE`, `VirtualSCSI`, `vmxnet3`, `ovf:capacity="68719476736"`, `<rasd:VirtualQuantity>4<`, `<rasd:VirtualQuantity>16384<`} {
		if !strings.Contains(ovf, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(ova.Render(ova.Params{Version: "0.1.0"}), "allowAuthBypass") {
		t.Error("the bypass is only there when asked for")
	}
	// Well-formed XML, and every Item's InstanceID unique.
	dec := xml.NewDecoder(strings.NewReader(ovf))
	ids := map[string]bool{}
	inID := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the OVF isn't well-formed: %v", err)
		}
		switch v := tok.(type) {
		case xml.StartElement:
			inID = strings.HasSuffix(fmt.Sprint(v.Name), " InstanceID}") // {space local}
		case xml.CharData:
			if inID {
				id := string(v)
				if ids[id] {
					t.Fatalf("InstanceID %s twice", id)
				}
				ids[id] = true
				inID = false
			}
		}
	}
}

func TestOVAWriterThroughTheKit(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
			t.Fatal("qemu-img isn't installed and SNEAKERS_REQUIRE_TOOLS is set")
		}
		t.Skip("qemu-img isn't installed")
	}
	dir, pins := fixtures.Build(t, fixtures.Options{})
	out := t.TempDir()
	paths, err := kitout.NewWriters(ova.OVA{}).Run(context.Background(), verify.LocalLayout(dir), pins, "ova", kitout.Options{Out: out, KitVersion: fixtures.Version})
	if err != nil || len(paths) != 1 {
		t.Fatalf("%v %v", paths, err)
	}
	f, err := os.Open(paths[0]) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	var names []string
	sums := map[string]string{}
	var mf string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		b, _ := io.ReadAll(tr)
		s := sha256.Sum256(b)
		sums[h.Name] = hex.EncodeToString(s[:])
		if strings.HasSuffix(h.Name, ".mf") {
			mf = string(b)
		}
	}
	if len(names) != 3 || filepath.Ext(names[0]) != ".ovf" || filepath.Ext(names[1]) != ".mf" || filepath.Ext(names[2]) != ".vmdk" {
		t.Fatalf("OVA order %v", names)
	}
	for _, n := range []string{names[0], names[2]} {
		if !strings.Contains(mf, "SHA256("+n+")= "+sums[n]) {
			t.Errorf("the manifest's digest for %s doesn't match", n)
		}
	}
}

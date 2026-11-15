// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// boxKeys reads the product Secrets the box wrote for k0s.
func boxKeys(t *testing.T, manifests string) map[string]map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(manifests, productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml")) // #nosec G304 -- the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]string{}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	for {
		var s struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
			StringData map[string]string `yaml:"stringData"`
		}
		if err := dec.Decode(&s); err != nil {
			return out
		}
		if s.Kind == "Secret" {
			out[s.Metadata.Namespace+"/"+s.Metadata.Name] = s.StringData
		}
	}
}

// The restore half of the recovery escrow, end to end with the real pieces
// and the Sneakers bundle's own product.yaml: a box makes its product keys,
// its escrow is decrypted with one recovery key and brought into a
// replacement box at first boot, and the replacement's product apply makes
// the vault's root key and the TOTP key the old box's (so the restored data
// opens) while every key the escrow doesn't carry is made anew.
func TestAReplacementBoxGetsTheOldBoxsProductKeysFromTheEscrow(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", productspec.File))
	if err != nil {
		t.Fatal(err)
	}
	slotFor := func() string {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, productspec.File), spec, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	loaded, err := productspec.Load(slotFor())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Escrow) == 0 {
		t.Fatal("the Sneakers product.yaml names no escrowed keys")
	}

	// Box A makes its keys.
	a := boxsecrets.Store{Dir: t.TempDir(), Manifests: t.TempDir()}
	if err := a.Ensure(slotFor()); err != nil {
		t.Fatal(err)
	}
	keysA := boxKeys(t, a.Manifests)

	// Its escrow carries each key the bundle names, sealed as
	// product-<product>-<name> (osadmin.ProductEscrowName).
	const product = "sneakers"
	custodyA := custodyIn(t, phase.Normal)
	want := map[string]string{}
	for _, e := range loaded.Escrow {
		v := keysA[e.Secret][e.Key]
		if v == "" {
			t.Fatalf("box A has no %s/%s to escrow", e.Secret, e.Key)
		}
		want[e.Name] = v
		if err := custodyA.Seal("product-"+product+"-"+e.Name, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	plain := escrowPlaintext(t, custodyA)

	// A replacement box imports it at first boot, then applies the product.
	custodyB := custodyIn(t, phase.Firstboot)
	if err := custodyB.ImportEscrow(plain); err != nil {
		t.Fatal(err)
	}
	b := boxsecrets.Store{Dir: t.TempDir(), Manifests: t.TempDir(), Restore: func(name string) (string, bool, error) {
		v, err := custodyB.Unseal("product-" + product + "-" + name)
		if err != nil {
			return "", false, nil
		}
		return string(v), true, nil
	}}
	if err := b.Ensure(slotFor()); err != nil {
		t.Fatal(err)
	}
	keysB := boxKeys(t, b.Manifests)

	for _, e := range loaded.Escrow {
		if got := keysB[e.Secret][e.Key]; got != want[e.Name] {
			t.Errorf("%s (%s/%s) is %q on the replacement box, the old box's was %q", e.Name, e.Secret, e.Key, got, want[e.Name])
		}
	}
	// A key the escrow doesn't carry is made anew, never copied.
	if keysA["sneakers/sneakers-bundled"]["postgres-password"] == "" || keysA["sneakers/sneakers-bundled"]["postgres-password"] == keysB["sneakers/sneakers-bundled"]["postgres-password"] {
		t.Error("the database password must be made anew on the replacement box")
	}
}

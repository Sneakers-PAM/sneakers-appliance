// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody_test

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"testing"

	"filippo.io/age"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
)

func custodyIn(t *testing.T, p phase.Phase) *keycustody.Custody {
	t.Helper()
	needCryptsetup(t)
	kc := keycustody.New(keycustody.Deps{
		Disk:      &fileDisk{dir: t.TempDir()},
		SealedDir: t.TempDir(),
		Phase:     func() phase.Phase { return p },
	})
	if err := kc.Initialize(ctx, keycustody.ModeKeyfile, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	return kc
}

func escrowPlaintext(t *testing.T, kc *keycustody.Custody) []byte {
	t.Helper()
	rec := ed25519Key(t)
	blob, err := kc.Escrow([]string{rec.pub})
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(blob), rec.id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestImportEscrowOnNewHardware(t *testing.T) {
	a := custodyIn(t, phase.Normal)
	if err := a.Seal("vault-root", []byte("box A root")); err != nil {
		t.Fatal(err)
	}
	if err := a.Seal("audit-key", []byte("box A audit")); err != nil {
		t.Fatal(err)
	}
	plain := escrowPlaintext(t, a)

	b := custodyIn(t, phase.Firstboot)
	if _, err := b.ImportEscrow(plain); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"vault-root": "box A root", "audit-key": "box A audit"} {
		got, err := b.Unseal(name)
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	if _, err := b.ImportEscrow(plain); !codes.Is(err, codes.KeyCustodyPhase) {
		t.Fatalf("a second import must be refused once root secrets exist, got %v", err)
	}
}

// A real box has sealed its own items before an admin can reach it (the SSH
// root key, the pepper, the host CA). The import keeps those, and brings in
// the old box's other items.
func TestImportEscrowKeepsTheItemsTheBoxSealedForItself(t *testing.T) {
	a := custodyIn(t, phase.Normal)
	for name, v := range map[string]string{"root-key": "box A ssh", "product-sneakers-vault-root-key": "box A vault"} {
		if err := a.Seal(name, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	plain := escrowPlaintext(t, a)

	b := custodyIn(t, phase.Firstboot)
	if err := b.Seal("root-key", []byte("box B ssh")); err != nil {
		t.Fatal(err)
	}
	res, err := b.ImportEscrow(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Imported, []string{"product-sneakers-vault-root-key"}) || !slices.Equal(res.Kept, []string{"root-key"}) {
		t.Fatalf("imported %v, kept %v", res.Imported, res.Kept)
	}
	for name, want := range map[string]string{"root-key": "box B ssh", "product-sneakers-vault-root-key": "box A vault"} {
		got, err := b.Unseal(name)
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	// Everything the escrow holds is sealed now: a second import has nothing to bring.
	if _, err := b.ImportEscrow(plain); !codes.Is(err, codes.KeyCustodyPhase) {
		t.Fatalf("a second import must be refused, got %v", err)
	}
}

func TestImportEscrowOnlyInFirstboot(t *testing.T) {
	a := custodyIn(t, phase.Normal)
	if err := a.Seal("vault-root", []byte("k")); err != nil {
		t.Fatal(err)
	}
	plain := escrowPlaintext(t, a)
	for _, p := range []phase.Phase{phase.Normal, phase.Install, phase.Enrol, phase.Mismatch} {
		if _, err := custodyIn(t, p).ImportEscrow(plain); !codes.Is(err, codes.KeyCustodyPhase) {
			t.Errorf("%s: want KEYCUSTODY_PHASE, got %v", p, err)
		}
	}
}

func TestImportEscrowRefusesBadContents(t *testing.T) {
	bad := map[string][]byte{
		"not json":      []byte("hello"),
		"wrong version": mustJSON(t, keycustody.EscrowContents{Version: 2, StateKey: make([]byte, keycustody.KeySize)}),
		"bad item name": mustJSON(t, keycustody.EscrowContents{Version: 1, StateKey: make([]byte, keycustody.KeySize), Items: map[string][]byte{"../x": []byte("v")}}),
	}
	for name, plain := range bad {
		kc := custodyIn(t, phase.Firstboot)
		if _, err := kc.ImportEscrow(plain); !codes.Is(err, codes.KeyCustodyInvalid) {
			t.Errorf("%s: want KEYCUSTODY_INVALID, got %v", name, err)
		}
		if _, err := kc.Unseal("x"); !codes.Is(err, codes.KeyCustodyNotFound) {
			t.Errorf("%s: a refused import left items behind", name)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
